# 🗄️ [보고서 03] 데이터베이스 스키마, 룰 문법 및 연동 API 상세 명세서

| 문서 관리 번호 | `IPS-DOC-2026-V1.0-03` | 버전 | `v1.0.0` |
| :--- | :--- | :--- | :--- |
| **작성 일자** | 2026-11-19 | **분류** | DB 스키마 및 API 명세서 (Database & API Specification) |
| **검토 부서** | 백엔드/DB 아키텍트, SOAR/SIEM 연동팀 | **상태** | Baseline 승인 |

---

## 1. 데이터베이스 아키텍처 개요 (Polyglot Persistence)

Pre-Firewall IDS/IPS의 특성상 초당 수십만 건의 이벤트 쓰기(Write)와 복잡한 정책/자산의 트랜잭션 무결성(ACID), 그리고 나노초 단위의 패킷 조회 속도를 동시에 만족해야 하므로 목적별 3계층 저장소를 구성합니다.

| 계층 | 저장소 엔진 | 주요 저장 데이터 | 설계 목적 및 특징 |
| :--- | :--- | :--- | :--- |
| **Tier-0 (Data Plane)** | **eBPF Maps & Shared Memory** | 실시간 차단 IP(LPM Trie), 세션 상태(Flow Table), Fast-Bypass 목록 | 나노초(ns) 단위의 Lock-free 패킷 조회 및 차단 집행 |
| **Tier-1 (Control Plane)** | **PostgreSQL 16+** | 탐지 정책/룰셋, 내부 자산(CMDB) 컨텍스트, 센서 노드 상태, RBAC/감사 로그 | 정책 버전 관리, 무결성 보장, KCMVP 암호화 컬럼 저장 |
| **Tier-2 (Log & Analytics)** | **ClickHouse** | 실시간 침입 탐지/차단 경보(Alert), 플로우 메타데이터(NetFlow/TLS/DNS), 트래픽 통계 | 초당 수십만 건(100K+ EPS) 실시간 압축 적재 및 서브초(Sub-second) OLAP 쿼리 |

---

## 2. [Tier-0] 데이터 플레인 인메모리(eBPF Maps) 스키마 (C Struct)

Tier 1(XDP)과 Tier 2(User-space DPI), 그리고 SOAR 연동 데몬이 공유하는 커널/유저 공간 맵 구조체입니다. (`bpf/include/common_maps.h` 참조)

```c
// 1. LPM Trie 기반 실시간 차단 IP/대역 맵 (BPF_MAP_TYPE_LPM_TRIE)
// SOAR, CTI 및 DPI 엔진이 공격자 발견 시 즉시 이 맵에 삽입하여 커널 진입 전 XDP_DROP 수행
struct lpm_ip_key {
    __u32 prefixlen;    // CIDR prefix (IPv4: 32, IPv6: 128)
    __u8  ip[16];       // IPv4-mapped IPv6 또는 순수 IPv6 주소
};

struct block_entry_val {
    __u64 expire_ts;    // 만료 타임스탬프 (ktime_get_ns 기준, 0이면 영구 차단)
    __u64 hit_packets;  // 차단된 누적 패킷 수 (Per-CPU 원자적 증가)
    __u64 hit_bytes;    // 차단된 누적 바이트 수
    __u32 rule_id;      // 차단을 유발한 룰 ID 또는 SOAR Playbook ID
    __u8  reason_code;  // 1: CTI_BAD_IP, 2: DDOS_RATE_LIMIT, 3: DPI_OFFLOAD, 4: SOAR_MANUAL
    __u8  action;       // 1: XDP_DROP, 2: XDP_PASS (Whitelist), 3: RATE_LIMIT
};

// 2. 5-Tuple 세션 및 Elephant Flow Shunting 맵 (BPF_MAP_TYPE_LRU_PERCPU_HASH)
struct flow_key {
    __u8  src_ip[16];
    __u8  dst_ip[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;        // IPPROTO_TCP(6), IPPROTO_UDP(17), IPPROTO_ICMP(1)
    __u16 vlan_id;
} __attribute__((packed));

struct flow_state_val {
    __u64 flow_id;          // 전역 고유 Flow ID (Snowflake 64-bit, PCAP 매핑용)
    __u64 last_seen_ns;
    __u8  bypass_dpi;       // 1로 설정 시 Tier 2(DPI)를 건너뛰고 XDP에서 반대 포트로 즉시 포워딩
    __u8  tcp_state;        // SYN_SENT, ESTABLISHED, FIN_WAIT 등
    __u16 app_proto;        // 식별된 L7 프로토콜 (HTTP2, TLS1.3, QUIC, DNS, SSH 등)
    __u32 threat_score;     // 누적 위협 점수 (임계치 초과 시 block_entry로 승격)
};
```

---

## 3. [Tier-1] 컨트롤 플레인 RDBMS 스키마 (PostgreSQL DDL)

중앙 관리 콘솔(EMS)에서 운영하는 핵심 테이블 명세입니다.

```sql
-- 1. 센서 노드 관리 테이블 (Active-Active 클러스터 및 Bypass NIC 상태 모니터링)
CREATE TABLE sensor_nodes (
    sensor_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname        VARCHAR(128) NOT NULL UNIQUE,
    cluster_group   VARCHAR(64) NOT NULL,                 -- 예: 'DMZ-PRE-FW-CLUSTER-01'
    deployment_mode VARCHAR(20) NOT NULL,                 -- 'INLINE_IPS', 'TAP_IDS', 'SHADOW'
    mgmt_ip         INET NOT NULL,
    bypass_nic_mode VARCHAR(20) NOT NULL DEFAULT 'AUTO',  -- 'AUTO'(Watchdog), 'FORCE_BYPASS', 'NORMAL'
    active_rule_ver INTEGER NOT NULL DEFAULT 0,
    cpu_usage_pct   NUMERIC(5,2),
    rx_pps          BIGINT,
    rx_bps          BIGINT,
    status          VARCHAR(20) NOT NULL,                 -- 'HEALTHY', 'DEGRADED_QOS', 'BYPASSED', 'OFFLINE'
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. 내부 보호 대상 자산 컨텍스트 테이블 (오탐 방지 및 Target-based Reassembly용)
CREATE TABLE protected_assets (
    asset_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_cidr         CIDR NOT NULL UNIQUE,                 -- 내부 서버 IP 또는 서브넷
    hostname        VARCHAR(128),
    os_family       VARCHAR(32) NOT NULL,                 -- 'LINUX', 'WINDOWS', 'BSD', 'SOLARIS' (TCP 재조합 정책 결정)
    os_version      VARCHAR(64),
    criticality     SMALLINT NOT NULL CHECK (criticality BETWEEN 1 AND 5), -- 1(낮음) ~ 5(핵심기반시설)
    running_services JSONB NOT NULL DEFAULT '[]',         -- 예: [{"port": 443, "app": "nginx", "tech": ["java", "spring"]}]
    known_cves      TEXT[] DEFAULT '{}',                  -- 취약점 스캐너 연동 결과 보유 CVE 목록
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_assets_ip_cidr ON protected_assets USING GIST (ip_cidr inet_ops);

-- 3. 탐지/차단 시그니처 룰 마스터 테이블
CREATE TABLE signature_rules (
    rule_id         INTEGER PRIMARY KEY,                  -- SID (1000000~ 커스텀, <1000000 벤더 기본)
    rev             INTEGER NOT NULL DEFAULT 1,
    title           VARCHAR(256) NOT NULL,
    category        VARCHAR(64) NOT NULL,                 -- 'EXPLOIT', 'DDOS', 'MALWARE_C2', 'RECON', 'POLICY'
    action          VARCHAR(16) NOT NULL,                 -- 'DROP', 'REJECT', 'ALERT', 'RATE_LIMIT', 'SHADOW_DROP'
    severity        SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 4), -- 1:Low, 2:Medium, 3:High, 4:Critical
    target_os       VARCHAR(32)[],                        -- 매칭 대상 OS (Asset 컨텍스트 연동용)
    target_tech     VARCHAR(64)[],                        -- 예: {'apache', 'php', 'mysql'}
    cve_ids         VARCHAR(32)[],                        -- 예: {'CVE-2021-44228'}
    mitre_tactic    VARCHAR(64),                          -- 예: 'TA0001 (Initial Access)'
    mitre_technique VARCHAR(32),                          -- 예: 'T1190'
    raw_rule_syntax TEXT NOT NULL,                        -- 실제 컴파일될 룰 원문
    is_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by      UUID,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. 컴플라이언스(CC인증/보안기능확인서)용 관리자 감사 로그 테이블 (위변조 방지 HMAC 포함)
CREATE TABLE audit_trails (
    audit_id        BIGSERIAL PRIMARY KEY,
    actor_id        UUID NOT NULL,
    actor_role      VARCHAR(32) NOT NULL,                 -- 'SYS_ADMIN', 'POLICY_ADMIN', 'AUDITOR'
    actor_ip        INET NOT NULL,
    action_type     VARCHAR(64) NOT NULL,                 -- 'RULE_UPDATE', 'POLICY_DEPLOY', 'PCAP_DOWNLOAD', 'BYPASS_TOGGLE'
    target_resource VARCHAR(256),
    before_state    JSONB,
    after_state     JSONB,
    result          VARCHAR(16) NOT NULL,                 -- 'SUCCESS', 'FAILURE'
    kcmvp_hmac      VARCHAR(128) NOT NULL,                -- 이전 레코드 해시와 결합된 체인형 HMAC-SHA256 서명값
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## 4. [Tier-2] 대용량 보안 이벤트 및 플로우 스키마 (ClickHouse DDL)

초당 10만 건 이상의 경보와 플로우 로그를 저장하고, SIEM 전송 및 대시보드 통계 쿼리를 0.1초 이내에 응답하기 위한 스키마입니다.

```sql
CREATE TABLE security_alerts (
    alert_id            UUID,
    flow_id             UInt64,                           -- PCAP 파일 및 Flow 로그 조인 키
    first_seen          DateTime64(6, 'Asia/Seoul'),      -- 마이크로초 단위 최초 탐지 시각
    last_seen           DateTime64(6, 'Asia/Seoul'),      -- 집계 윈도우 내 마지막 탐지 시각
    aggregated_count    UInt32 DEFAULT 1,                 -- 동일 공격 압축 횟수 (SIEM EPS 절감 핵심)
    sensor_id           LowCardinality(String),
    execution_tier      Enum8('TIER1_XDP'=1, 'TIER2_DPI'=2, 'TIER3_AI'=3),
    action_taken        Enum8('ALERT'=1, 'DROP'=2, 'REJECT'=3, 'RATE_LIMIT'=4, 'SHADOW_DROP'=5, 'OFFLOAD_FW'=6),
    
    -- 네트워크 5-Tuple 및 지리 정보
    src_ip              IPv6,
    src_port            UInt16,
    src_country         FixedString(2),
    src_asn             UInt32,
    dst_ip              IPv6,
    dst_port            UInt16,
    vlan_id             UInt16,
    ip_proto            UInt8,
    app_proto           LowCardinality(String),           -- 'HTTP/2', 'TLSv1.3', 'QUIC', 'DNS', 'SMB'
    
    -- 룰 및 위협 컨텍스트 정보
    rule_id             UInt32,
    rule_rev            UInt16,
    rule_category       LowCardinality(String),
    base_severity       UInt8,                            -- 1~4
    asset_criticality   UInt8,                            -- 0(미등록) 또는 1~5
    vuln_match_factor   Float32,                          -- 0.1(OS/앱 불일치) ~ 1.5(보유 CVE 정확히 일치)
    final_risk_score    Float32,                          -- 최종 산출 위험도 점수 (관제 우선순위 정렬 기준)
    cve_id              LowCardinality(String),
    mitre_attack_id     LowCardinality(String),
    
    -- L7 / 암호화 / AI 분석 메타데이터
    http_host           String,
    http_uri            String,
    http_method         LowCardinality(String),
    tls_sni             String,
    tls_ja4_hash        FixedString(36),                  -- JA4 클라이언트 지문
    ai_anomaly_score    Float32,                          -- Tier 3 AI 모델 추론 점수 (0.0 ~ 1.0)
    
    -- 포렌식 증거
    payload_snippet     String,                           -- 매칭된 페이로드 앞뒤 256 바이트 (Base64)
    pcap_storage_uri    String                            -- 예: 's3://forensics/2026/11/19/flow_98123412.pcapng'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(first_seen)
ORDER BY (toStartOfMinute(first_seen), final_risk_score, src_ip, dst_ip, rule_id)
TTL toDateTime(first_seen) + INTERVAL 90 DAY DELETE;
```

---

## 5. 하이브리드 탐지/차단 룰(Rule) 문법 명세

보안팀의 기존 운영 노하우를 100% 승계하기 위해 **Suricata / Snort 3 표준 문법과 완벽히 호환**되면서도, 본 시스템 고유 기능인 **XDP 하드웨어 오프로딩, 자산 컨텍스트 매칭, AI 점수 결합** 키워드를 확장(Extension)한 문법입니다.

```snort
# [예시 1] Log4Shell (CVE-2021-44228) 탐지 + 자산 컨텍스트 검증 + XDP 자동 차단 오프로딩 + 전후 패킷 PCAP 덤프
drop http $EXTERNAL_NET any -> $HOME_NET any (
    msg:"[CRITICAL] Apache Log4j2 JNDI RCE Attempt (Normalized)";
    flow:established,to_server;
    http.uri.normalized; content:"${jndi:"; nocase; fast_pattern;
    pcre:"/\$\{(?:jndi|lower|upper|env|sys|date)[\s:]/i";
    
    # --- 차세대 확장 키워드 (Custom Extensions) ---
    context.target_tech:"java";                         # 타겟 서버가 Java 기반일 때만 Critical 경보 (아니면 Risk Score 90% 감산)
    context.cve:"CVE-2021-44228";
    xdp.offload_block:src_ip, ttl 3600;                 # 탐지 즉시 해당 공격자 IP를 Tier 1(eBPF Map)에 1시간 동안 등록하여 후속 패킷 커널 진입 차단
    forensic.pcap:pre_pkts 15, post_pkts 30;            # 공격 패킷 이전 15개, 이후 30개 패킷을 묶어 PCAP 타임머신 덤프 생성
    
    classtype:attempted-admin;
    sid:2001001; rev:3;
)

# [예시 2] 비복호화 암호화 트래픽(TLS 1.3) Cobalt Strike C2 통신 탐지 (JA4 지문 + AI 비콘 주기성 결합)
reject tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"[MALWARE-C2] Encrypted Cobalt Strike Beacon Detected via JA4 & AI";
    tls.ja4; content:"t13d1516h2_8daaf6152771_e5627efa2ab1";
    tls.cert_age:<86400;                                # 생성된 지 24시간 미만인 신생 TLS 인증서
    ai.beacon_score:>0.85;                              # Tier 3 AI 엔진이 계산한 주기적 비콘 통신 확률 85% 이상
    
    xdp.offload_block:dst_ip, ttl 86400;                # C2 서버 IP를 24시간 동안 Tier 1에서 원천 차단
    soar.webhook:"playbook_isolate_infected_host";      # SOAR 플레이북 즉시 트리거 (내부 감염 호스트 EDR 격리)
    sid:2001002; rev:1;
)
```

---

## 6. 컨트롤 플레인 및 외부 보안 시스템 연동 API 명세 (OpenAPI 3.0 / gRPC)

모든 API는 **mTLS(상호 인증서 인증)** 또는 **JWT(KCMVP 서명)**를 통해 인증되며, 전용 관리 인터페이스(MGMT Port)로만 호출 가능합니다.

### 6.1 주요 REST API 엔드포인트 요약

| 분류 | Method | Endpoint URI | 호출 주체 | 기능 설명 |
| :--- | :--- | :--- | :--- | :--- |
| **SOAR 대응** | `POST` | `/api/v1/mitigation/xdp-block` | SOAR / NGFW | 공격자 IP/대역을 전 센서의 Tier-1(eBPF Map)에 10ms 내 즉시 차단 등록 |
| **SOAR 대응** | `DELETE` | `/api/v1/mitigation/xdp-block/{ip}` | SOAR / 관제사 | 차단된 IP를 즉시 해제 |
| **포렌식** | `GET` | `/api/v1/forensics/pcap/{flow_id}` | SIEM / SOAR | 특정 침해 경보(`flow_id`)와 연결된 전후 패킷 `.pcapng` 스트림 다운로드 |
| **정책 관리** | `POST` | `/api/v1/policies/rules/hot-reload` | EMS 콘솔 | RCU 기반으로 패킷 유실 없이 전체 센서의 시그니처 룰셋 무중단 업데이트 |
| **시뮬레이션** | `POST` | `/api/v1/policies/shadow-evaluate` | 보안팀 운영자 | 신규 룰을 실제 차단 적용하기 전, Shadow 모드로 N시간 테스트 예약 |
| **자산 연동** | `PUT` | `/api/v1/context/assets/sync` | CMDB / 스캐너 | 내부 서버 자산 정보(OS, 오픈 포트, CVE) 일괄 업데이트 (오탐 계산용) |
| **HA / 제어** | `POST` | `/api/v1/sensors/{id}/bypass` | EMS / 비상제어 | 특정 센서의 하드웨어 Bypass NIC 릴레이를 강제 Open(통과)으로 전환 |

### 6.2 핵심 API 요청/응답 상세 페이로드 (JSON Schema)

#### ① [SOAR 연동] 실시간 초고속 IP 차단 위임 API (`POST /api/v1/mitigation/xdp-block`)
* **Request Body:**
```json
{
  "target_ips": [
    "203.0.113.45/32",
    "198.51.100.0/24",
    "2001:db8:abcd::/48"
  ],
  "action": "XDP_DROP",
  "ttl_seconds": 7200,
  "reason_code": "SOAR_PLAYBOOK_AUTO",
  "incident_ticket_id": "INC-2026-1119-0042",
  "propagate_to_bgp_flowspec": true,
  "target_clusters": ["ALL"]
}
```
* **Response (`200 OK`):**
```json
{
  "status": "SUCCESS",
  "transaction_id": "tx_99a8b7c6-1234-5678",
  "applied_sensors_count": 4,
  "ebpf_map_insertion_time_ms": 3.4,
  "bgp_flowspec_announced": true,
  "expires_at": "2026-11-19T12:35:57+09:00"
}
```

#### ② [SIEM / Kafka 연동] 실시간 경보 출력 표준 포맷 (`soc.ips.alerts`)
```json
{
  "schema_version": "1.0",
  "alert_id": "e4d909c2-90d0-4f88-9e1a-112233445566",
  "flow_id": "18446744073709551615",
  "timestamps": {
    "first_seen": "2026-11-19T10:35:10.112045+09:00",
    "last_seen": "2026-11-19T10:35:20.998120+09:00",
    "aggregated_count": 1420
  },
  "sensor": {
    "sensor_id": "sns-dmz-01",
    "cluster": "DMZ-PRE-FW-CLUSTER-01",
    "tier": "TIER2_DPI",
    "mode": "INLINE_IPS"
  },
  "verdict": {
    "action": "DROP",
    "xdp_offloaded": true,
    "xdp_offload_ttl": 3600
  },
  "network": {
    "src_ip": "185.220.101.44",
    "src_port": 54122,
    "src_geo": "DE",
    "src_asn": 205100,
    "dst_ip": "10.20.30.15",
    "dst_port": 443,
    "vlan_id": 102,
    "proto": "TCP",
    "app_proto": "HTTP/2"
  },
  "threat": {
    "rule_id": 2001001,
    "rule_rev": 3,
    "title": "[CRITICAL] Apache Log4j2 JNDI RCE Attempt (Normalized)",
    "category": "EXPLOIT",
    "cve": "CVE-2021-44228",
    "mitre": {
      "tactic": "TA0001",
      "technique": "T1190"
    },
    "scoring": {
      "base_severity": 4,
      "asset_criticality": 5,
      "vuln_match_factor": 1.5,
      "final_risk_score": 30.0,
      "context_note": "타겟 자산(10.20.30.15)에 Java/Spring 환경 및 CVE-2021-44228 미패치 상태가 확인되어 위험도 가중치(1.5x)가 부여됨."
    }
  },
  "forensics": {
    "matched_buffer": "http.uri.normalized",
    "payload_sample_b64": "R0VUIC9hcGkvdjEvbG9naW4/dXNlcj0ke2puZGk6bGRhcDovLzE4NS4yMjAuMTAxLjQ0OjEzODkvRXhwbG9pdH0gSFRUUC8yLjA=",
    "pcap_download_url": "https://ems.internal.soc/api/v1/forensics/pcap/18446744073709551615"
  }
}
```

#### ③ [무중단 운영] Shadow 모드 시뮬레이션 리포트 조회 (`GET /api/v1/policies/shadow-report/{job_id}`)
```json
{
  "shadow_job_id": "shd_20261119_01",
  "tested_rules": [2001055, 2001056],
  "duration_hours": 24,
  "summary": {
    "total_would_drop_packets": 482,
    "affected_unique_internal_assets": 2,
    "false_positive_probability": "HIGH (87.4%)"
  },
  "recommendation": "DO_NOT_ENABLE_BLOCK",
  "analysis_details": [
    {
      "rule_id": 2001055,
      "internal_src_ip": "10.10.5.100 (사내 ERP 배치 서버)",
      "reason": "사내 ERP 서버가 매시 정각에 외부 금융결제원 API로 전송하는 정상 XML 전문이 룰 2001055의 SQL Injection 패턴과 매칭됨. 해당 IP 예외 처리(Whitelist) 후 차단 모드 전환 권장."
    }
  ]
}
```
