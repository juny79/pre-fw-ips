# 🧪 [보고서 04] 코어 엔진 프로토타입 구현 및 성능·보안인증 검증 계획서

| 문서 관리 번호 | `IPS-DOC-2026-V1.0-04` | 버전 | `v1.0.0` |
| :--- | :--- | :--- | :--- |
| **작성 일자** | 2026-11-19 | **분류** | 프로토타입 구현 및 검증 계획서 (Prototype & Verification Plan) |
| **검토 부서** | 코어 엔진 개발팀, QA/인증평가팀 | **상태** | Baseline 승인 |

---

## 1. 코어 엔진 프로토타입 구조 개요

코어 엔진은 **Tier 1 커널 공간(C 언어 기반 eBPF/XDP)**과 **Tier 2 유저 공간(Rust 언어 기반 AF_XDP + Vectorscan + RCU)**의 하이브리드 구조로 작성하여, 메모리 안전성(Memory Safety)과 물리 장비(ASIC)급 성능을 동시에 달성합니다.

* **실제 구현 소스 코드 위치:**
  * 커널/유저 공유 맵 헤더: [`bpf/include/common_maps.h`](../../bpf/include/common_maps.h)
  * Tier 1 eBPF/XDP 커널 프로그램: [`bpf/xdp_pre_filter.bpf.c`](../../bpf/xdp_pre_filter.bpf.c)
  * Tier 2 Rust RCU 룰 엔진 및 DPI 워커: [`ips-core/src/engine/rcu_ruleset.rs`](../../ips-core/src/engine/rcu_ruleset.rs)

### 1.1 핵심 프로토타입 설계 메커니즘
1. **Tier 1 (`xdp_pre_filter.bpf.c`):**
   * `BPF_MAP_TYPE_LPM_TRIE`를 통해 최대 200만 개의 악성 IP/CIDR를 나노초 단위로 조회하여 커널 메모리(`sk_buff`) 할당 전에 `XDP_DROP` 처리.
   * `BPF_MAP_TYPE_LRU_PERCPU_HASH`를 통해 Lock 없이 5-Tuple 세션을 조회하고, `bypass_dpi == 1`로 마킹된 대용량 안전 세션(Elephant Flow)은 `BPF_MAP_TYPE_DEVMAP`을 통해 반대쪽 NIC 포트로 즉시 하드웨어 리다이렉트.
   * 정밀 검사가 필요한 패킷은 `BPF_MAP_TYPE_XSKMAP`을 통해 동일 CPU 코어의 유저 공간 `AF_XDP` 소켓으로 Zero-copy 전달.
2. **Tier 2 (`rcu_ruleset.rs`):**
   * `ArcSwap<CompiledRuleEngine>`을 사용해 워커 스레드가 뮤텍스(Mutex)나 RwLock 없이 현재 활성화된 시그니처 룰셋 포인터를 즉시 읽고 패턴 매칭 수행.
   * 자산 컨텍스트(`lookup_asset_context`)를 결합해 타겟 서버와 무관한 OS/기술 스택 공격은 차단하지 않고 위험도 점수를 감산하여 오탐(False Positive) 원천 방지.

---

## 2. 성능 및 대역폭 벤치마크 계획 (Performance & Latency)

### 2.1 테스트베드 구성
* **트래픽 생성기 (Traffic Generator):** **Cisco TRex** (Stateful/Stateless L7 트래픽 생성기) 또는 Keysight CyPerf (100Gbps 광 인터페이스 직결).
* **DUT (Device Under Test):** 40Gbps 기준 범용 서버 (Dual Xeon Gold 32C, 128GB DDR5, Silicom 40G Bypass NIC), 시그니처 룰 **25,000개 활성화** 상태.

### 2.2 핵심 성능 합격 기준표 (KPI & Pass Criteria)

| 시험 항목 | 시험 방법 및 트래픽 프로파일 | 목표 합격 기준 (40G 센서 기준) | 비고 |
| :--- | :--- | :--- | :--- |
| **1. RFC 2544 처리량 (Throughput)** | 64B, 512B, 1518B 패킷 크기별 Frame Loss 0% 최대 대역폭 측정 | - 1518B / IMIX: **40 Gbps (Line-rate)**<br>- 64B 최소 패킷: **59.5 Mpps** (XDP 계층) | 패킷 드롭률 0.000% |
| **2. 실환경 IMIX L7 DPI 성능** | 실제 기업 트래픽 비율 (HTTP/2 40%, TLS 1.3 35%, DNS 10%, SMB/기타 15%) + 25,000개 룰 매칭 | **38 Gbps 이상** 유지 (CPU 사용률 75% 이하) | Vectorscan + Elephant Flow Bypass 작동 포함 |
| **3. 인라인 전달 지연시간 (Latency)** | 패킷이 RX 포트로 진입하여 DPI 검사를 마치고 TX 포트로 나갈 때까지의 시간 | - 평균(Avg): **< 45 μs** (마이크로초)<br>- 99.9 백분위(p99.9): **< 120 μs** | 물리 장비(보통 30~80μs)와 동등 수준 입증 |
| **4. CPS (초당 신규 연결 생성률)** | 초당 대량의 TCP 3-Way Handshake + HTTP GET 요청 생성 | **1,200,000 CPS** 이상 (방화벽 앞단 세션 부하 흡수력 검증) | Per-Core Lockless Flow Table 검증 |
| **5. 대용량 DDoS 방어 생존성** | 정상 업무 트래픽 10Gbps + **SYN Flood / Bad IP 공격 30Gbps** 동시 주입 | 정상 업무 트래픽 10Gbps **패킷 유실 0%**, 공격 트래픽 30Gbps는 Tier-1(XDP)에서 **100% Drop** | 후단 방화벽 CPU/세션 영향 0% 확인 |

---

## 3. 고가용성(HA) 및 무중단 생존성 테스트 (Fail-Safe Verification)

보안팀이 가장 우려하는 **"소프트웨어 오류로 인한 전사 인터넷 단절"**이 절대 발생하지 않음을 실증합니다.

1. **시나리오 A: IPS 코어 프로세스 강제 종료 (`kill -9` Test)**
   * **수행 방법:** 20Gbps 실시간 화상회의/금융 트랜잭션 트래픽이 흐르는 도중 `kill -9 <ips-core-pid>` 실행.
   * **합격 기준:** Bypass NIC의 하드웨어 Watchdog이 데몬 Heartbeat 중단을 **10ms 이내**에 감지하여 광/구리 릴레이를 물리적으로 단락(Fail-Open)시키고, **TCP 세션 끊김 없이 1~2개 이하의 패킷 지연만으로 통신 유지**.
2. **시나리오 B: OS 커널 패닉 및 서버 전원 케이블 발거 (Power-Cut Test)**
   * **수행 방법:** `echo c > /proc/sysrq-trigger`로 리눅스 커널 패닉을 유발하거나 서버 파워서플라이 케이블을 물리적으로 뽑음.
   * **합격 기준:** 전원 상실 즉시 Bypass NIC 코일이 비활성화되며 **< 5ms 이내**에 물리 바이패스 모드로 전환되어 후단 방화벽과의 링크가 유지됨.
3. **시나리오 C: 무중단 시그니처 룰 리로드 (Zero-Downtime Hot-Reload Test)**
   * **수행 방법:** 30Gbps 트래픽 처리 중 신규 시그니처 룰 5,000개를 추가하여 `/api/v1/policies/rules/hot-reload` 호출 (연속 50회 반복).
   * **합격 기준:** RCU 포인터 스왑을 통해 **패킷 드롭 0개(0 Packet Loss)**, Latency 스파이크 **+20μs 이내** 유지.

---

## 4. 공격 탐지율 및 우회 공격(Evasion) 방어 검증 시나리오

* **테스트 도구:** **Pytbull**, **Metasploit Framework**, **Atomic Red Team**, **tcpreplay (실제 침해사고 PCAP 재생)**.

| 검증 영역 | 세부 공격 기법 (Test Case) | 기대 동작 및 합격 기준 |
| :--- | :--- | :--- |
| **L3/L4 파편화 및 세그먼트 중첩 우회** | IP Fragmentation Overlap 및 TCP Segment Overlap (공격 페이로드를 1바이트씩 쪼개고 더미 데이터를 겹쳐 전송) | 타겟 서버의 OS(`protected_assets` 테이블의 Linux/Windows 설정)와 동일하게 스트림을 재조합하여 **100% 탐지 및 차단** |
| **L7 다중 난독화 우회** | SQLi 및 Log4Shell 공격 구문에 `URL 인코딩 + Unicode + SQL 주석(/**/) + HTTP 파이프라이닝` 복합 적용 | L7 Normalizer가 평문으로 복원한 후 Vectorscan 매칭을 수행하여 **우회 실패(차단 성공)** |
| **비복호화 암호화 C2 탐지** | TLS 1.3으로 암호화된 Cobalt Strike / Sliver C2 비콘 통신 발생 | 페이로드 복호화 없이 **JA4 지문 + 신생 인증서 + Tier 3 AI 주기성(Beaconing) 점수** 결합으로 탐지 및 `TCP RST` 차단 |
| **오탐(False Positive) 억제 검증** | 사내 개발자가 정상 업무용으로 SQL 쿼리가 포함된 JSON API 호출 또는 대용량 파일 업로드 수행 | Asset Context Scoring 및 Shadow 모드 검증을 통해 **정상 업무 트래픽 오차단 0건** |

---

## 5. 공공기관/금융권 컴플라이언스 및 보안인증 대응 매핑표

국가·공공기관 납품을 위해 필수적인 **「국가용 보안요구사항 - 침입방지시스템(IPS) V3.0」** 및 **보안기능확인서** 시험 항목을 충족하기 위한 설계 매핑입니다.

| 국가용 보안요구사항 항목 | 요구사항 세부 내용 | 본 아키텍처 설계 반영 내역 |
| :--- | :--- | :--- |
| **1. 보안 감사 (FAU)** | 감사 데이터 생성, 저장소 고갈 시 대응, 감사 로그 위변조 방지 및 조회 권한 통제 | - PostgreSQL `audit_trails` 테이블에 모든 관리자 행위 기록<br>- 이전 로그와 연결된 **체인형 KCMVP HMAC-SHA256 서명**으로 DB 직접 조작 시에도 위변조 즉시 탐지<br>- 디스크 임계치(80%, 90%) 도달 시 가장 오래된 일반 로그 덮어쓰기 또는 관리자 경보 발송 |
| **2. 암호 지원 (FCS)** | 국정원 검증필 암호모듈(KCMVP)을 사용한 중요 데이터 암호화 및 통신 구간 보호 | - 관리 콘솔(HTTPS), 센서-관리서버(gRPC over TLS), 설정/키 저장 시 **KCMVP 인증 모듈(ARIA-256-GCM, SHA-256/512)** 호출 |
| **3. 식별 및 인증 (FIA)** | 관리자 다중 인증(MFA), 연속 인증 실패 시 계정 잠금, 패스워드 복잡도 강제 | - 연속 5회 로그인 실패 시 30분간 계정/IP 잠금<br>- OTP(TOTP) 기반 2차 인증 및 RBAC(`SYS_ADMIN`, `POLICY_ADMIN`, `AUDITOR`) 분리 |
| **4. 자체 보호 및 무결성 (FPT)** | 보안 기능 실행 파일 및 설정 데이터의 자체 무결성 검사, 시간 동기화(NTP) | - 부팅 시 및 일 1회(또는 관리자 요청 시) `ips-core` 바이너리와 `.bpf.o` 오브젝트에 대한 HMAC 무결성 검증 수행 (실패 시 안전 모드 전환 및 경보) |
