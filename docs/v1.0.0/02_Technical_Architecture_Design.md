# 📐 [보고서 02] Pre-Firewall S/W IDS/IPS 상세 기술 아키텍처 설계서

| 문서 관리 번호 | `IPS-DOC-2026-V1.0-02` | 버전 | `v1.0.0` |
| :--- | :--- | :--- | :--- |
| **작성 일자** | 2026-11-19 | **분류** | 상세 기술 아키텍처 설계서 (Technical Architecture Design) |
| **검토 부서** | 코어 엔진 개발팀, SOC 아키텍처팀 | **상태** | Baseline 승인 |

---

## 1. 전사 보안 아키텍처 내 배치 및 연동 구조 (Enterprise Security Context)

보안팀 입장에서 Pre-Firewall IDS/IPS는 단독 장비가 아니라 **전사 보안 메시(Security Mesh)의 최전방 센서이자 1차 집행기(Enforcer)**로 작동합니다.

```text
                         [ 외부 인터넷 (ISP / BGP Router) ]
                                         │
                                  (Optical / Copper)
                                         ▼
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ [1차 방어선: Pre-Firewall S/W IDS/IPS (Active-Active HA Cluster)]               ┃
┃                                                                                 ┃
┃  ┌───────────────────────────────────────────────────────────────────────────┐  ┃
┃  │ Hardware Bypass NIC (Intel E810 / Silicom) - Optical Relay Watchdog       │  ┃
┃  └─────────────┬───────────────────────────────────────────────▲─────────────┘  ┃
┃                │ (RX Queues: RSS)                              │ (TX Queues)    ┃
┃                ▼                                               │                ┃
┃  ┌───────────────────────────┐   AF_XDP Zero-Copy   ┌──────────┴─────────────┐  ┃
┃  │ Tier 1: XDP/eBPF Engine   │ ───────────────────► │ Tier 2: User-Space DPI │  ┃
┃  │ - Bad IP / GeoIP Drop     │                      │ - Lockless Flow Table  │  ┃
┃  │ - SYN Cookie / DDoS Mitig.│                      │ - TCP Reassembly       │  ┃
┃  │ - Elephant Flow Bypass    │                      │ - Vectorscan + L7 Parse│  ┃
┃  └───────────────────────────┘                      └──────────┬─────────────┘  ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┿━━━━━━━━━━━━━━━━┛
                                         │                       │ (Async RingBuf)
                         (정화된 트래픽) │                       ▼
                                         ▼        ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
                         [ 2차 방어선: 차세대 방화벽 (NGFW) ]   ┃ Tier 3: Smart Analytics & EMS ┃
                                         │        ┃ - AI Anomaly (ONNX)           ┃
                                         ▼        ┃ - PCAP Time-Machine           ┃
                         [ SSL Visibility / 내부 코어 스위치 ]  ┗━━━━━━┯━━━━━━━┯━━━━━━━┯━━━━━━━━┛
                                                                 │       │       │
          ┌──────────────────────────────────────────────────────┘       │       └──────────────────────┐
          ▼ (BGP Flowspec / Dynamic ACL API)                             ▼ (CEF/Kafka/gRPC)             ▼ (STIX/TAXII 2.1)
┌─────────────────────────┐                                   ┌─────────────────────┐        ┌─────────────────────┐
│ 라우터 & 차세대 방화벽  │                                   │  SOC: SIEM & SOAR   │        │ 위협 인텔리전스(CTI)│
│ - 영구 차단 위임 (Offload)│                                   │ - 상관분석/플레이북 │        │ - KISA C-TAS / 국정원│
└─────────────────────────┘                                   └─────────────────────┘        └─────────────────────┘
```

### 1.1 타 보안 시스템과의 역할 분담 (Defense-in-Depth)
* **vs 라우터/Anti-DDoS:** IPS의 Tier 1(eBPF/XDP)이 L3/L4 볼륨 공격과 SYN Flood를 즉각 방어하며, 임계치를 넘는 초대형 공격 감지 시 상위 BGP 라우터에 **BGP Flowspec** 신호를 보내 ISP 단에서 Blackhole 처리하도록 연동합니다.
* **vs 차세대 방화벽(NGFW):**
  * **세션 테이블 보호:** 방화벽 진입 전에 스캐닝(Reconnaissance), 비정상 TCP 플래그, Half-open 세션을 IPS가 100% 소멸시켜 방화벽의 세션 고갈(Exhaustion)을 방지합니다.
  * **차단 위임(Offloading):** IPS가 L7 페이로드 분석을 통해 특정 공격자 IP를 '확정적 위협'으로 판단하면, REST API를 통해 후단 방화벽의 Dynamic Block List에 등록하거나 자체 Tier 1(eBPF Map)으로 내려보내 이후 패킷이 DPI 엔진을 소모하지 않도록 합니다.

---

## 2. 데이터 플레인(Data Plane) 상세 아키텍처

물리 장비(ASIC/FPGA)를 범용 x86 서버로 대체하기 위해, **커널 네트워크 스택을 완전히 우회(Bypass)**하고 **Shared-Nothing(무공유) 멀티코어 아키텍처**를 채택합니다.

### 2.1 패킷 처리 파이프라인 (Zero-Copy Pipeline)

1. **NIC 하드웨어 계층 (RSS & Flow Director)**
   * NIC의 **Symmetric RSS(Receive Side Scaling)** 해시 함수를 설정하여, 양방향 트래픽(`SrcIP:SrcPort <-> DstIP:DstPort`)이 항상 **동일한 RX 큐와 동일한 CPU 코어**에 할당되도록 보장합니다.
   * 이를 통해 멀티코어 간 Lock(잠금) 경합 없이 각 코어가 독립적으로 TCP 세션 상태와 재조합 버퍼를 관리합니다.

2. **Tier 1: 커널 공간 초고속 필터 (Native XDP / eBPF)**
   * NIC 드라이버가 인터럽트(또는 NAPI 폴링)를 발생시키는 즉시 `sk_buff` 구조체 할당 전에 실행됩니다.
   * **주요 eBPF Maps 구조:**
     * `blacklist_lpm_trie` (`BPF_MAP_TYPE_LPM_TRIE`): CTI 및 SOAR에서 내려받은 수백만 개의 악성 IP/CIDR 목록. 매칭 시 `XDP_DROP` (나노초 단위 처리).
     * `conntrack_fast_bypass` (`BPF_MAP_TYPE_LRU_PERCPU_HASH`): Tier 2 DPI 엔진이 "안전한 대용량 플로우(예: 백업, 대용량 패치 다운로드, 검증된 화이트리스트 비디오 스트림)"로 마킹한 세션은 Tier 2로 올리지 않고 즉시 반대쪽 NIC 포트로 `XDP_REDIRECT` 하여 CPU 부하를 극적으로 줄입니다(**Elephant Flow Shunting**).
     * `synproxy_state`: SYN Flood 공격 시 커널/DPI 진입 전 XDP 레벨에서 SYN Cookie를 생성·검증하여 3-Way Handshake가 완료된 정상 세션만 Tier 2로 전달합니다.

3. **Tier 2: 유저 공간 DPI 엔진 (`AF_XDP` 또는 `DPDK` PMD)**
   * XDP에서 `XDP_REDIRECT`된 패킷은 **UMEM (User-space Memory)** 영역을 공유하는 `AF_XDP` 소켓(또는 DPDK `rte_mbuf`)을 통해 메모리 복사(Copy) 없이 유저 공간 워커 스레드로 전달됩니다.
   * 각 Worker Thread는 특정 물리 CPU 코어에 고정(`pthread_setaffinity_np`)되며, `isolcpus` 및 `nohz_full` 커널 파라미터로 OS 스케줄러의 간섭을 완전히 배제합니다.

### 2.2 NUMA 및 메모리 아키텍처 설계
* **Hugepages 필수 할당:** TLB(Translation Lookaside Buffer) Miss를 방지하기 위해 `1GB Hugepages`를 사용하여 패킷 버퍼(UMEM/mbuf), 세션 테이블, TCP 재조합 링버퍼를 사전 할당(Pre-allocation)합니다. 런타임 중 동적 메모리 할당(`malloc`/`free`)은 엄격히 금지하고 Object Pool 방식을 사용합니다.
* **NUMA Locality 보장:** 듀얼 소켓 서버의 경우, PCIe 슬롯에 꽂힌 NIC가 속한 NUMA Node(예: Node 0)의 CPU 코어와 RAM만 해당 NIC의 패킷을 처리하도록 바인딩하여 QPI/UPI 병목을 원천 차단합니다.

---

## 3. 심층 패킷 분석(DPI) 및 탐지 엔진 상세 설계

Tier 2 워커 스레드 내부에서 패킷이 거치는 **6단계 인라인 분석 파이프라인**입니다.

```text
[Packet In] ──► (1) L2~L4 Decoder ──► (2) Flow Manager ──► (3) IP Defrag & TCP Reassembly
                                                                        │
[Verdict] ◄── (6) Rule Eval & Action ◄── (5) Vectorscan MPM ◄── (4) L7 App-Layer Parser & Normalizer
```

### 3.1 단계별 세부 동작
1. **L2~L4 디코더 및 정합성 검사 (Sanity Check)**
   * VLAN(802.1Q, QinQ), VXLAN, Geneve, GRE, MPLS 등 터널링 헤더를 디캡슐레이션(Decapsulation)하여 내부 패킷을 추출합니다.
   * 체크섬 오류, 비정상 헤더 길이, Land Attack(SrcIP=DstIP), 비정상 TCP 플래그 조합(SYN+FIN 등)을 즉각 탐지/차단합니다.
2. **플로우 매니저 (Per-Core Flow Table)**
   * 5-Tuple(`SrcIP, DstIP, SrcPort, DstPort, Proto`) + `VLAN ID`를 키로 하는 Per-Core 해시 테이블을 조회합니다.
   * 세션 상태(SYN_SENT, ESTABLISHED, FIN_WAIT 등), 타임아웃 타이머, 누적 바이트/패킷 카운터를 업데이트합니다.
3. **우회 방어용 IP 재조합 및 TCP 스트림 재조합 (Anti-Evasion)**
   * **Target-Based IP Defrag / TCP Reassembly:** 공격자가 패킷 조각을 겹치게(Overlapping) 보내 IPS와 실제 타겟 서버가 서로 다르게 재조합하도록 유도하는 공격(Ptacek & Newsham 기법)을 막기 위해, 내부 자산 DB와 연동하여 타겟 서버의 OS 정책(Linux, Windows, BSD 등)과 동일한 방식으로 세그먼트를 재조합합니다.
   * **Zero-copy Sliding Window:** 패킷 페이로드 포인터만 연결 리스트/트리(RB-Tree)로 관리하여 연속된 스트림 뷰를 제공합니다.
4. **L7 프로토콜 파서 및 데이터 정규화 (App-Layer Parser & Normalizer)**
   * 포트 번호에 의존하지 않고 **Protocol Detection(보초 바이트 및 패턴 검사)**을 통해 비표준 포트로 숨은 HTTP, TLS, SSH, DNS, SMB, RDP 등을 식별합니다.
   * **메모리 안전 파서:** 파서 자체의 취약점(Buffer Overflow)을 막기 위해 모든 L7 파서는 **Rust(Nom 라이브러리 등)**로 작성합니다.
   * **다중 인코딩 정규화:** HTTP URI, Header, Body에 적용된 `%XX`(URL), `\uXXXX`(Unicode), Base64, HTML Entity, 경로 탐색(`/../`, `/./`), SQL 주석 삽입(`/**/`) 등을 평문 표준 형태로 디코딩한 후 탐지 엔진에 넘깁니다.
5. **다중 패턴 매칭 가속 (Multi-Pattern Matching - Vectorscan)**
   * 수만 개의 시그니처 룰을 하나씩 대조하면 성능이 급락하므로, 룰에 포함된 핵심 고정 문자열(`fast_pattern`)들을 모아 단일 Aho-Corasick/SIMD 오토마타로 컴파일합니다.
   * Intel AVX-512 / ARM NEON 명령어를 활용하는 **Vectorscan**을 통해 한 번의 스트림 스캔(Single-pass)으로 후보 룰(Candidate Rules)만 수십 나노초 내에 추려냅니다.
6. **정밀 룰 평가 및 판정 (Rule Evaluation & Verdict)**
   * 후보 룰에 대해서만 PCRE2(JIT 컴파일), 바이트 점프(`byte_jump`, `byte_test`), 프로토콜 필드 조건(`http.uri`, `tls.sni`, `dns.query`)을 최종 검증합니다.
   * **Verdict 종류:**
     * `PASS`: 즉시 TX 큐로 전송.
     * `DROP`: 패킷 폐기 (공격자에게 아무 응답 안 함 - Stealth).
     * `REJECT`: 패킷 폐기 후 공격자 및 서버 양쪽에 `TCP RST` 또는 `ICMP Unreachable` 패킷을 생성하여 전송(세션 즉시 종료).
     * `RATE_LIMIT`: Token Bucket 알고리즘에 따라 초과 패킷만 Drop.

### 3.2 암호화 트래픽(TLS 1.3 / QUIC) 분석 아키텍처
방화벽 앞단에서 복호화 장비 없이도 암호화 위협을 잡아내는 구조입니다.
* **JA3 / JA3S / JA4+ 지문 추출:** TLS Client Hello 및 Server Hello(QUIC Initial 패킷 포함)에서 TLS 버전, Cipher Suites, Extensions, Elliptic Curves 순서를 조합해 해시값을 생성합니다. 알려진 악성코드(Cobalt Strike, Metasploit, Trickbot 등)의 C2 통신을 복호화 없이 99% 식별 및 차단합니다.
* **인증서 및 SNI 분석:** Let's Encrypt 등 무료 인증서 중 생성된 지 24시간 미만인 도메인, 자체 서명(Self-signed) 인증서, SNI 헤더와 실제 IP 소유 조직(ASN)의 불일치 여부를 검사합니다.
* **인바운드 TLS 복호화 (옵션):** 기관 내부 웹서버(DMZ)로 들어오는 트래픽에 한해, KMS(Key Management System)와 연동하여 TLS Session Key 또는 Private Key(PFS가 아닌 경우 또는 eBPF TLS Master Secret 추출 에이전트 연동)를 통해 인라인 복호화 검사를 수행합니다.

---

## 4. 지능형 분석 계층 (Tier 3: Out-of-Band AI & Forensics)

인라인 패킷 처리 지연(Latency)에 0%의 영향을 주도록, Tier 2에서 Lock-free Ring Buffer(Shared Memory)를 통해 복사된 **메타데이터 및 의심 패킷**만 비동기로 분석합니다.

### 4.1 경량 AI 추론 파이프라인 (ONNX Runtime)
* **Feature Extractor (C++/Rust):** 플로우별로 패킷 크기 분포(Mean/StdDev), 패킷 도착 간격(IAT: Inter-Arrival Time), 업/다운로드 비율, 엔트로피(Entropy - 암호화/압축 여부 측정), DNS 질의 문자열의 자음/모음/숫자 비율 등 40여 개 피처를 실시간 계산합니다.
* **탐지 모델 구성:**
  1. **DGA (Domain Generation Algorithm) 탐지:** Character-level CNN / Bi-LSTM 모델을 ONNX로 변환하여 초당 수만 건의 DNS 질의 중 악성코드가 생성한 랜덤 도메인을 1ms 이내에 판별.
  2. **C2 Beaconing 탐지:** 시계열 주기성 분석(Fast Fourier Transform 및 지터(Jitter) 분석)을 통해 내부 감염 PC가 외부 C2 서버로 일정한 주기로 신호를 보내는 행위 탐지.
  3. **Zero-day 볼륨/스텔스 공격 탐지:** Autoencoder 기반 비지도 학습 모델로, 평소 기관의 시간대별/요일별 트래픽 프로파일에서 벗어나는 이상 징후(Anomaly Score) 산출.

### 4.2 PCAP 타임머신 (Forensic Ring-Buffer)
침해사고 발생 시 보안팀이 가장 절실히 필요로 하는 **"공격 성공 직전/직후의 전체 패킷(Full Packet Capture)"**을 제공합니다.
* NVMe SSD 전용 파티션(Direct I/O)에 순환 버퍼(Ring-Buffer) 형태로 최근 N시간~N일 치의 원시 패킷을 지속 기록합니다.
* 메모리 상에는 각 세션별 최근 N개 패킷을 유지하다가, 특정 세션에서 High/Critical 경보가 발생하는 순간 **공격 패킷 이전(Pre-attack) 패킷부터 이후(Post-attack) 패킷까지를 하나로 묶어 별도 영구 스토리지에 `.pcapng` 파일로 자동 덤프**하고 SIEM 경보에 다운로드 링크를 첨부합니다.

---

## 5. 컨트롤 플레인(Control Plane) 및 무중단 운영 아키텍처

### 5.1 무중단 룰셋 및 정책 리로드 (RCU 기반 Hot-Swap)
보안팀이 하루에도 수차례 차단 룰이나 유해 IP를 추가할 때, 패킷 유실이나 세션 끊김이 발생해서는 안 됩니다.

```text
[Worker Threads] ─── (Read Pointer A) ──► [ Active Rule Engine Instance v1.0 ]
                                          
[Management Daemon] ── (Compile in Background) ──► [ Standby Rule Engine Instance v1.1 ]
        │
        └──► (Atomic Pointer Swap: A -> B)
        
[Worker Threads] ─── (Read Pointer B) ──► [ Active Rule Engine Instance v1.1 ]
                                          [ Old v1.0 freed after Grace Period ]
```

* **RCU (Read-Copy-Update) 패턴 적용:**
  1. 관리 데몬이 별도 코어(Management Core)에서 신규 룰셋을 파싱하고 Vectorscan DB를 백그라운드로 컴파일합니다.
  2. 컴파일이 완료되면 각 워커 스레드가 참조하는 엔진 포인터를 원자적 연산(`atomic_exchange` / `ArcSwap`)으로 새 인스턴스로 교체합니다.
  3. 모든 워커 스레드가 기존 패킷 처리를 마치고 새 포인터를 참조하는 것(Grace Period)을 확인한 후 이전 메모리를 해제합니다. (패킷 드롭 **0개** 보장)

### 5.2 고가용성(HA) 및 장애 복구(Fail-Safe) 메커니즘
방화벽 앞단 장비의 장애는 곧 전사 인터넷 마비를 의미하므로 **4단계 안전장치**를 구현합니다.

| 단계 | 장애 유형 | 감지 방식 | 대응 동작 (Fail-Safe Action) | 복구 목표 시간 |
| :--- | :--- | :--- | :--- | :--- |
| **Lv 1** | **트래픽 폭주 (과부하)** | Worker CPU 사용률 > 90% 또는 RX Queue Drop 발생 | **Adaptive QoS 작동:** 우선순위가 낮은 L7 인포메이션 룰 검사 생략, 대용량 플로우 XDP Fast-Pass 전환 | 즉시 (0 ms) |
| **Lv 2** | **특정 워커 스레드 행(Hang)** | 내부 Watchdog 스레드가 워커의 Heartbeat 카운터 정지 감지 | 해당 코어를 RSS 테이블에서 제외(리밸런싱)하거나, 소프트웨어 브릿지 커널 포워딩으로 전환 | < 50 ms |
| **Lv 3** | **IPS 데몬 크래시 / OS 패닉** | Bypass NIC의 하드웨어 Watchdog 타이머 만료 (Heartbeat 중단) | **Hardware Bypass 작동:** NIC 내부의 광/구리 물리 릴레이가 닫히며(Closed) 서버를 물리적 케이블 상태로 직결 (Fail-Open) | **< 10 ms** |
| **Lv 4** | **장비 하드웨어 영구 고장** | Active-Active 클러스터 간 Keepalived(VRRP) 및 상태 동기화 단절 | 인접 HA 노드가 전체 트래픽을 인수. (세션 동기화 프로토콜을 통해 기존 TCP 연결 유지) | < 100 ms |

---

## 6. 보안 시스템 연동 인터페이스 및 로그 파이프라인

### 6.1 오탐(False Positive) 방지를 위한 자산 컨텍스트 연동 (Asset Context DB)
* 기관의 취약점 점검 도구, CMDB, 또는 NDR로부터 내부 서버 자산 정보(`IP, OS 종류/버전, 오픈 포트, 구동 중인 웹서버/WAS 종류, 중요도`)를 JSON/REST API로 주기적으로 동기화합니다.
* **Contextual Scoring 수식:**
  $$\text{Final Risk Score} = \text{Rule Severity} \times \text{Asset Criticality} \times \text{Vulnerability Match Factor}$$
  * 예: 공격자가 Apache Struts 취약점 공격을 시도했으나, 대상 서버(`DstIP`)가 내부 자산 DB상 `Windows Server + IIS`인 경우, `Vulnerability Match Factor = 0.1`이 적용되어 차단/경보 등급을 `Info`로 낮추어 보안팀의 오탐 분석 피로도를 획기적으로 줄입니다.

### 6.2 고속 로그 파이프라인 및 SIEM 비용 최적화
방화벽 앞단에서는 초당 수만 건의 스캐닝/DDoS 이벤트가 발생할 수 있습니다. 이를 그대로 SIEM에 전송하면 SIEM EPS(Events Per Second) 라이선스가 초과되고 스토리지가 마비됩니다.
* **Smart Event Aggregator (로그 압축기):**
  * 동일한 `SrcIP -> DstIP` 및 동일한 `Rule ID`로 발생하는 이벤트는 최초 1건만 즉시 전송하고, 이후 트래픽은 Time-Window(예: 10초/60초) 동안 인메모리에서 집계하여 `Count=54,200, FirstSeen=..., LastSeen=...` 형태의 **단일 요약 로그**로 압축 전송합니다.
* **표준 출력 인터페이스:**
  * **SIEM 연동:** Syslog (RFC 5424 over TLS), CEF (ArcSight), LEEF (QRadar), Kafka Producer 내장.
  * **SOAR 양방향 API (OpenAPI 3.0 / gRPC):**
    * `POST /api/v1/mitigation/xdp-block` (SOAR 플레이북이 특정 IP를 N분간 즉시 차단 명령 - eBPF Map에 즉시 반영)
    * `GET /api/v1/forensics/pcap/{flow_id}` (SOAR가 침해사고 티켓 생성 시 자동으로 해당 공격의 PCAP 파일 다운로드)

---

## 7. 컴플라이언스 및 자체 보안 아키텍처 (Self-Protection)

국가·공공기관(국정원 보안적합성 검증, 보안기능확인서) 및 금융권 도입을 위한 필수 설계 요소입니다.

1. **관리 플레인 물리적/논리적 분리 (Out-of-Band Management):**
   * 인라인 트래픽을 처리하는 NIC 포트(Data Port)를 통해서는 관리 콘솔(EMS)이나 SSH에 절대 접근할 수 없도록 커널 네임스페이스(`netns`)를 완전히 분리하고, 전용 관리 포트(MGMT Port)로만 제어 트래픽을 허용합니다.
2. **국정원 검증필 암호모듈(KCMVP) 탑재:**
   * 관리 웹 UI(TLS 1.2/1.3), 센서-관리서버 간 gRPC 통신, DB 내 관리자 패스워드/개인키 저장(ARIA-256GCM, SEED, SHA-256/512), 감사 로그 위변조 방지 전자서명에 KCMVP 인증 C/C++ 라이브러리를 래핑(Wrapping)하여 적용합니다.
3. **실행 파일 및 룰 무결성 검증 (Integrity Check):**
   * 시스템 부팅 시(Secure Boot 연동) 및 매일 지정된 주기로 IPS 코어 엔진 바이너리와 주요 설정 파일의 해시값(HMAC-SHA256)을 검증하며, 위변조 감지 시 즉시 관리자에게 경보를 발송하고 감사 로그를 남긴 후 안전 모드로 전환합니다.
4. **역할 기반 접근 제어(RBAC) 및 감사 추적(Audit Trail):**
   * `최고관리자(System Admin)`, `정책관리자(Policy Admin)`, `관제모니터요원(Auditor)`으로 권한을 엄격히 분리하고, 룰 수정·정책 배포·패킷 덤프 열람 등 모든 관리자 행위를 삭제 불가능한 별도 감사 로그(WORM 스토리지 연동 지원)에 기록합니다.

---

## 8. 하드웨어 사이징 및 성능 목표 기준표 (Reference Specification)

| 구분 | 10 Gbps 급 센서 (중견기업/지사) | 40 Gbps 급 센서 (대기업/공공 본청) | 100 Gbps 급 센서 (데이터센터/ISP급) |
| :--- | :--- | :--- | :--- |
| **CPU** | 1x Intel Xeon Silver / AMD EPYC (16 Cores 이상) | 2x Intel Xeon Gold / AMD EPYC (32 Cores 이상) | 2x Intel Xeon Platinum / AMD EPYC (64 Cores 이상) |
| **RAM** | 64 GB DDR4/DDR5 ECC | 128 GB DDR5 ECC (8ch 구성) | 256 GB ~ 512 GB DDR5 ECC |
| **Bypass NIC** | Dual/Quad Port 10G Bypass NIC (Intel X710/E810 기반) | Dual Port 40G/25G Bypass NIC (PCIe 4.0 x16) | Dual Port 100G SmartNIC / Bypass NIC (PCIe 5.0 x16) |
| **Storage** | OS: 2x 480GB SSD (RAID 1)<br>PCAP: 2TB NVMe SSD | OS: 2x 480GB SSD (RAID 1)<br>PCAP: 2x 4TB NVMe (RAID 0/10) | OS: 2x 960GB SSD (RAID 1)<br>PCAP: 4x 8TB Enterprise NVMe |
| **목표 성능** | - L7 DPI: **10 Gbps**<br>- XDP Filtering: **14.88 Mpps**<br>- 동시 세션: **500만** | - L7 DPI: **40 Gbps**<br>- XDP Filtering: **59.5 Mpps**<br>- 동시 세션: **2,000만** | - L7 DPI: **100 Gbps**<br>- XDP Filtering: **148.8 Mpps**<br>- 동시 세션: **5,000만** |
| **지연 시간** | 평균 **< 50 μs** (마이크로초) | 평균 **< 50 μs** (마이크로초) | 평균 **< 80 μs** (마이크로초) |
