# 🖥️ [보고서 05] SOC 통합 보안 관제(EMS) 백엔드 서버 및 웹 대시보드 구축 보고서

| 문서 관리 번호 | `IPS-DOC-2026-V1.1-05` | 버전 | `v1.1.0` |
| :--- | :--- | :--- | :--- |
| **작성 일자** | 2026-11-21 | **분류** | 백엔드 서버 및 웹 관제 UI 구축 명세서 (Backend & Web EMS Specification) |
| **구현 소스** | `ems-server/app.py`, `ems-server/static/index.html` | **상태** | Release 승인 |

---

## 1. 구축 배경 및 최종 목적

기업 및 공공기관 보안팀(SOC/CERT)의 최종 목표는 단일 장비의 패킷 처리 속도를 넘어 **전체 보안 아키텍처(경계 라우터 $\rightarrow$ 1차 방어선 Pre-Firewall IDS/IPS $\rightarrow$ 2차 방어선 차세대 방화벽(NGFW) $\rightarrow$ 내부 코어 스위치/TAP $\rightarrow$ 내부 서버군 및 SIEM/SOAR/CTI 보안솔루션)** 전체 단계에서 **Pre-Firewall IDS/IPS가 각 후단 장비의 생존성과 보안 퍼포먼스를 어떻게 극대화하는지 실시간으로 입증하고 제어**하는 것입니다.

이를 위해 정적 목업(Mockup)을 넘어 실제 **FastAPI + SQLite3(PostgreSQL 스키마 호환) + 인메모리 eBPF Map 시뮬레이터** 기반의 풀스택 백엔드 서버(`ems-server`)와 1초 주기로 실시간 연동되는 고도화된 웹 관제 대시보드(`v1.1.0`)를 구축했습니다.

---

## 2. 백엔드 서버(`ems-server`) 아키텍처 및 구성 진행 과정

### 2.1 전체 백엔드 모듈 구조

```text
pre-fw-ips/
└── ems-server/
    ├── app.py                  # FastAPI 기반 컨트롤 플레인, 5단계 아키텍처 텔레메트리 엔진, PCAP Hex 생성기
    ├── control_plane.db        # 자동 초기화되는 SQLite3 DB (protected_assets, signature_rules, audit_trails)
    └── static/
        └── index.html          # 실시간 캔버스 차트, 32코어 RSS 매트릭스, 5탭 SOC 워크벤치 웹 UI
```

### 2.2 단계별 백엔드 구축 프로세스 (Step-by-Step)

#### Step 1: Tier-0 인메모리 eBPF LPM Trie 및 런타임 상태 엔진 구성
* `RUNTIME_STATE` 딕셔너리 내에 커널 `BPF_MAP_TYPE_LPM_TRIE` (`blacklist_map`)와 동일한 데이터 구조를 인메모리로 구현했습니다.
* 1초마다 호출되는 텔레메트리 루프에서 현재 시나리오(`normal`, `volumetric`, `apt`, `evasion`)와 IPS 활성화 여부(`ips_enabled`), 하드웨어 Bypass NIC 모드(`INLINE` vs `FAIL_OPEN`)에 따라 각 차단 엔트리의 `hit_packets` 및 `hit_bytes`가 실시간으로 원자적 증가합니다.

#### Step 2: Tier-1 컨트롤 플레인 RDBMS (`control_plane.db`) 자동 초기화 및 시딩(Seeding)
* 서버 기동 시(`@app.on_event("startup")`) `init_db()`가 실행되어 `v1.0.0` 설계서의 PostgreSQL 스키마와 1:1로 대응되는 3개 핵심 테이블을 생성하고 초기 운영 데이터를 시딩합니다.
  1. **`protected_assets` (내부 보호 서버 CMDB):** `dmz-api-gw-01`(Ubuntu 24.04, Java/Spring), `auth-sso-win01`(Windows Server 2022, IIS/.NET), `erp-core-batch`(RHEL 9.4, Oracle) 등 5개 대표 서버 자산의 OS 계열, 구동 서비스 스택, 보유 CVE, 오탐 억제 누적 건수를 관리합니다.
  2. **`signature_rules` (차세대 확장 시그니처 룰):** `context.target_tech`, `xdp.offload_block`, `forensic.pcap`, `ai.beacon_score` 확장 키워드가 포함된 핵심 룰셋을 저장합니다.
  3. **`audit_trails` (KCMVP 체인형 HMAC-SHA256 보안 감사 로그):** 국가용 보안요구사항 V3.0(FAU/FCS)을 준수하기 위해, 관리자가 대시보드에서 IPS 토글, Bypass NIC 전환, RCU 룰 스왑, SOAR IP 차단을 수행할 때마다 **직전 감사 레코드의 HMAC 해시값과 현재 명령을 결합한 체인형 HMAC-SHA256 서명(`compute_kcmvp_hmac`)**을 생성하여 DB 위변조를 원천 탐지합니다.

#### Step 3: 전사 보안 아키텍처 5단계(STAGE 1 ~ 5) 상관 퍼포먼스 계산 엔진 (`compute_5stage_architecture_metrics`)
* 단순 랜덤 수치가 아니라 1차 방어선(STAGE 2)의 상태 변화가 후단 장비(STAGE 3~5)에 미치는 인과관계를 수학적으로 모델링했습니다.
  * **Pre-FW IPS 가동(`INLINE`) 시:**
    * 40Gbps 복합 DDoS 유입 시 Tier 1(eBPF/XDP)이 25.2Gbps, Tier 2(Rust DPI)가 0.8Gbps를 사전 소멸시키고, 5.2Gbps의 대용량 안전 스트림(Elephant Flow)을 Fast-Shunt 처리합니다.
    * 결과적으로 후단 **차세대 방화벽(STAGE 3)에는 100% 정화된 14.0Gbps 트래픽만 도달**하여 방화벽 CPU(22.3%)와 세션 테이블 점유율(17.9%, 89만 세션)이 안전 상태를 유지하고, 내부 서버 가용성(STAGE 5 SLA)은 **99.999%**를 달성합니다.
  * **Pre-FW IPS 미적용 또는 `FAIL_OPEN` 직결 시:**
    * 26.0Gbps의 악성 SYN Flood와 스캐닝 패킷이 방화벽을 직격하여 **방화벽 세션 테이블(500만 세션)이 100% 고갈(`CRITICAL_EXHAUSTED`)**되고, 코어 스위치 패킷 드롭률이 38.5%로 치솟으며, 내부 서버 서비스 가용성(SLA)이 **31.8%로 붕괴**되는 현상을 실시간 시계열 차트와 지표로 보여줍니다.

#### Step 4: 32-Core Symmetric RSS & AF_XDP 부하 매트릭스 및 PCAP Hex/ASCII 포렌식 엔진
* 듀얼 소켓(NUMA Node 0, Node 1) 32코어 서버 환경에서 각 코어별 XDP 커널 처리율(`xdp_cpu_pct`), Rust DPI 처리율(`dpi_cpu_pct`), `Mpps` 처리량을 실시간 산출합니다.
* `/api/v1/forensics/pcap/{flow_id}` 엔드포인트는 공격 탐지 순간의 Ethernet/IPv4/TCP 헤더와 페이로드를 바이트 스트림으로 조립하여 **16바이트 정렬 Hex / ASCII 덤프(`build_hex_dump_lines`)**, **원본 난독화 패킷 vs L7 정규화(Normalized) 페이로드 비교**, **Pre/Post 패킷 타임라인**을 반환합니다.

---

## 3. REST API 엔드포인트 명세 (`ems-server`)

| Method | Endpoint | 설명 |
| :--- | :--- | :--- |
| `GET` | `/` | 고도화된 SOC 통합 보안 관제 웹 대시보드(`index.html`) 렌더링 |
| `GET` | `/api/v1/architecture/telemetry` | 5단계 전사 보안 아키텍처 실시간 지표, 시계열 데이터(24틱), 32코어 부하 매트릭스, eBPF 차단 맵 조회 |
| `POST` | `/api/v1/architecture/control` | 시나리오 변경(`normal`/`volumetric`/`apt`/`evasion`), IPS ON/OFF, Bypass NIC 릴레이 전환 (KCMVP 감사로그 자동 기록) |
| `POST` | `/api/v1/policies/rules/hot-reload` | RCU(`ArcSwap`) 무중단 룰셋 핫스왑 실행 (패킷 드롭 0개, 스왑 소요시간 ms 반환) |
| `POST` | `/api/v1/mitigation/xdp-block` | SOAR 연동 또는 관제사 수동 IP/CIDR 즉시 차단 (`blacklist_map` 삽입 및 BGP Flowspec 공지) |
| `DELETE` | `/api/v1/mitigation/xdp-block` | Tier-0 eBPF 맵에서 특정 IP/CIDR 차단 즉시 해제 |
| `GET` | `/api/v1/alerts` | Smart Aggregator로 압축된 실시간 위협 경보 목록 조회 |
| `GET` | `/api/v1/forensics/pcap/{flow_id}` | 특정 경보 플로우의 PCAP 타임머신 Hex/ASCII 덤프, 전후 패킷 타임라인, 위험도 공식 분해 조회 |
| `GET` | `/api/v1/context/assets` | SQLite/PostgreSQL `protected_assets` 내부 보호 서버 CMDB 목록 조회 |
| `GET` | `/api/v1/policies/rules` | SQLite/PostgreSQL `signature_rules` 확장 시그니처 룰셋 조회 |
| `GET` | `/api/v1/compliance/audits` | 체인형 KCMVP HMAC-SHA256 서명이 포함된 보안 감사 추적 로그 조회 |

---

## 4. 백엔드 서버 구동 및 웹 브라우저 접속 방법

### 4.1 서버 실행 명령어
```powershell
python C:\Users\user\.gemini\antigravity\scratch\pre-fw-ips\ems-server\app.py
```
* 기본 바인딩 주소 및 포트: `http://127.0.0.1:8090`

### 4.2 주요 검증 시나리오 가이드
1. **실시간 시계열 차트 및 32코어 부하 확인:** 웹페이지 접속 즉시 중앙의 캔버스 시계열 차트(`WAN 총 유입` vs `IPS 사전 차단` vs `NGFW 도달 대역폭`)와 우측 `32-Core Symmetric RSS` 매트릭스가 1초마다 실시간 갱신됩니다.
2. **A/B 방화벽 생존성 비교:** 상단의 **`[IPS 미적용 (방화벽 직결)]`** 버튼을 클릭하면 시계열 차트에서 빨간색(IPS 차단) 라인이 0으로 떨어지고 초록색(방화벽 유입) 라인이 40Gbps로 치솟으며 STAGE 3 방화벽이 `CRITICAL_EXHAUSTED`로 마비되는 과정을 실시간으로 확인할 수 있습니다.
3. **SOAR/eBPF 즉시 차단 및 KCMVP 감사 로그 검증:** 하단 **`② Tier-0 eBPF/XDP 실시간 차단 제어`** 탭에서 악성 IP(예: `198.51.100.77/32`)를 차단 등록하면 즉시 테이블에 추가되어 패킷 카운터가 올라가며, **`⑤ KCMVP 보안 감사 추적`** 탭에 체인형 HMAC-SHA256 서명과 함께 기록됩니다.
