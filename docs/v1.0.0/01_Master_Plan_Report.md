# 📋 [보고서 01] 차세대 Pre-Firewall 소프트웨어 기반 IDS/IPS 개발 종합기획서

| 문서 관리 번호 | `IPS-DOC-2026-V1.0-01` | 버전 | `v1.0.0` |
| :--- | :--- | :--- | :--- |
| **작성 일자** | 2026-11-19 | **분류** | 종합기획서 (Master Plan Report) |
| **검토 부서** | 기업/공공기관 보안팀(SOC/CERT), 인프라 아키텍처팀 | **상태** | Baseline 승인 |

---

## 1. 프로젝트 개요 및 배경 (Executive Summary)

### 1.1 개발 배경
* **물리 장비의 한계:** 기존 하드웨어 어플라이언스 기반 IDS/IPS는 도입 및 유지보수 비용이 높고, 클라우드/하이브리드 환경 확장에 따른 유연성이 떨어지며, 트래픽 급증 시 하드웨어 교체(Scale-up) 외에는 대응이 어렵습니다.
* **방화벽 앞단(1차 방어선) 배치의 필요성:** 방화벽은 상태 기반(Stateful) 세션 테이블을 유지하므로, 대규모 DDoS, SYN Flood, 비정상 스캐닝 트래픽이 방화벽에 직접 도달할 경우 방화벽 자체의 세션 고갈(Exhaustion)로 전체 네트워크가 마비될 수 있습니다. 따라서 방화벽 전단에서 악성 트래픽과 볼륨 공격을 1차적으로 정밀 필터링(Pre-filtering)해야 합니다.

### 1.2 프로젝트 목표
* **고성능 패킷 처리:** COTS(범용 x86/ARM 서버) 환경에서 커널 바이패스(eBPF/XDP, DPDK) 기술을 활용해 물리 장비 수준의 **Line-rate(10Gbps ~ 100Gbps) 처리 성능** 및 **Sub-millisecond 지연시간** 달성.
* **지능형 다계층 탐지/차단:** L3/L4 볼륨 공격부터 L7 페이로드(DPI), AI 기반 비정상 행위 탐지까지 아우르는 하이브리드 엔진 구축.
* **보안 생태계 완벽 통합:** 기업/공공기관 보안팀이 운영 중인 방화벽, SIEM, SOAR, 위협 인텔리전스(TI)와 유기적으로 연동되는 중앙 집중형 관리 체계 구축.
* **공공/금융 컴플라이언스 준수:** CC인증, 보안기능확인서, 국정원 암호모듈 검증(KCMVP) 등 공공기관 도입 필수 요건 충족.

---

## 2. 네트워크 배치 및 전체 시스템 아키텍처

### 2.1 네트워크 배치 구조 (Topology)
방화벽 전단(WAN 라우터와 방화벽 사이)에 위치하며, 기관의 환경에 따라 두 가지 모드를 동시 또는 선택적으로 지원합니다.

```text
[Internet / WAN Router]
          │
          ▼
┌─────────────────────────────────────────────────────────┐
│  [1차 방어선] 차세대 S/W IDS/IPS (In-line Mode)         │
│   ├─ L2/L3/L4 초고속 필터링 (XDP/eBPF: DDoS, 위협 IP)   │
│   ├─ L7 심층 패킷 분석 (DPDK + DPI: 시그니처, 프로토콜) │
│   └─ AI 이상징후 분석 (Out-of-band 비동기 스레드)       │
└─────────┬──────────────────────────────────┬────────────┘
          │ (정화된 정상 트래픽)             │ (경보/로그/차단정보)
          ▼                                  ▼
[2차 방어선: 차세대 방화벽(NGFW)]     [SOC 통합보안관제]
          │                           (SIEM / SOAR / CTI)
          ▼
   [내부망 / DMZ]
```

* **In-line (IPS) 모드:** Transparent Bridge(L2) 형태로 동작하여 IP 설정 없이 물리적 케이블 중간에 삽입. 장애 발생 시 네트워크 단절을 막기 위한 **하드웨어 Bypass NIC(Optical/Copper Watchdog) 연동** 및 **소프트웨어 Fail-Open** 필수 지원.
* **Tap / Span (IDS) 모드:** 스위치 포트 미러링 또는 네트워크 TAP 장비를 통해 패킷 사본만 수신하여 탐지 및 사후 분석(Forensic) 수행 (비동기 TCP Reset 패킷 주입을 통한 의사 차단 지원).

### 2.2 소프트웨어 엔진 아키텍처 (3-Tier Packet Pipeline)
물리 장비를 대체하기 위해 리눅스 기본 네트워크 스택(Kernel Network Stack)의 병목을 제거한 **3단계 고속 파이프라인**으로 설계합니다.

1. **Tier 1: Fast-Path 필터링 계층 (eBPF / XDP 기반)**
   * NIC 드라이버 레벨에서 패킷이 메모리(`sk_buff`)에 할당되기 전에 처리.
   * **역할:** 위협 인텔리전스(TI) 기반 악성 IP/GeoIP 즉각 Drop, SYN Cookie를 이용한 SYN Flood 방어, 비정상 단편화 패킷 차단, 화이트리스트 트래픽 Fast-Pass.
2. **Tier 2: Deep-Path 정밀 분석 계층 (DPDK / AF_XDP + Multi-thread DPI)**
   * User-space로 Zero-copy 전달된 패킷에 대해 CPU 코어별(RSS pinning) 무잠금(Lockless) 분석 수행.
   * **역할:** TCP 스트림 재조합(Reassembly), 프로토콜 디코딩(HTTP/2, HTTP/3(QUIC), DNS, SMB, TLS 등), 정규표현식 가속기(Intel Hyperscan/Vectorscan) 기반 시그니처 매칭.
3. **Tier 3: Smart-Path 지능형 분석 계층 (비동기 메시지 큐 연동)**
   * 인라인 트래픽 지연을 유발하지 않도록 플로우 메타데이터(NetFlow/IPFIX 형태)와 의심 패킷 샘플을 추출하여 별도 워커 노드로 전달.
   * **역할:** 머신러닝 기반 제로데이 공격 탐지, 암호화 트래픽(TLS) JA3/JA3S/JA4 지문 분석, DGA(도메인 생성 알고리즘) 및 C&C 비콘(Beaconing) 행위 탐지.

---

## 3. 핵심 기능 명세 (보안팀 실무 관점)

기업 및 공공기관 보안팀(SOC)이 1차 방어선에서 가장 필요로 하는 핵심 기능들을 정의합니다.

### 3.1 위협 탐지 및 차단 엔진 (Detection & Prevention)
* **Pre-Firewall 볼륨/세션 보호 기능:**
  * 방화벽 세션 테이블 보호를 위한 IP당 동시 세션 제한(Rate Limiting), CPS(Connections Per Second) 임계치 제어.
  * Port Scan, Xmas Scan, Null Scan 등 정찰(Reconnaissance) 행위 원천 차단.
* **고도화된 시그니처 및 프로토콜 검증:**
  * Snort 3 / Suricata 호환 룰셋 지원 및 자체 커스텀 룰 에디터 제공.
  * RFC 규격에 위배되는 프로토콜 변조(Protocol Anomaly) 및 버퍼 오버플로우, SQL Injection, 원격 코드 실행(RCE), Log4Shell 등 주요 CVE 취약점 공격 페이로드 차단.
* **우회 공격(Evasion) 방어:**
  * IP 단편화(Fragmentation) 및 TCP 세그먼트 중첩(Overlap) 공격을 방어하기 위한 OS별 타겟 기반 재조합(Target-based Reassembly).
  * Base64, URL 인코딩, Unicode, 이중 인코딩 등 난독화된 페이로드 자동 정규화(Normalization).
* **암호화 트래픽(TLS/QUIC) 가시성 확보:**
  * **비복호화 분석:** TLS Handshake 메타데이터(SNI, 인증서 유효성/자체서명 여부, 암호화 스위트) 및 **JA3/JA4 Fingerprint**를 통한 악성코드 통신 및 비인가 툴(Tor, VPN 등) 탐지.
  * **선택적 복호화(SSL Visibility):** 인바운드 서버 보호를 위한 서버 개인키 등록 복호화 및 외부 SSL 가시성 장비 연동(ICAP/TAP) 지원.

### 3.2 오탐(False Positive) 최소화 및 운영 안정성
보안팀이 IPS를 In-line 차단 모드로 전환하지 못하는 가장 큰 이유는 **'정상 업무 트래픽 차단(오탐)'에 대한 부담**입니다. 이를 해결하기 위한 기능을 탑재합니다.
* **Shadow (Simulation) 모드:** 신규 룰 적용 전, 실제 차단은 하지 않고 "차단되었을 트래픽"만 별도 대시보드로 시뮬레이션하여 영향도 사전 검증.
* **비즈니스 컨텍스트 연동(Asset-aware):** 내부 자산 관리 DB와 연동하여, 공격 타겟 서버의 OS/어플리케이션 환경과 무관한 공격(예: 리눅스 웹서버를 향한 Windows IIS 취약점 공격)은 경보 우선순위를 자동으로 낮추어 관제 피로도(Alert Fatigue) 감소.
* **자동 예외 처리 추천:** 반복 발생하는 정상 사내 트래픽 패턴을 학습하여 화이트리스트/예외 룰 생성을 관제사에게 추천.

### 3.3 종합 보안 시스템 연동 (SOC Ecosystem Integration)
단독 장비가 아닌 전체 보안 아키텍처의 유기적 일부로 동작합니다.
* **차세대 방화벽(NGFW) 연동:** IPS에서 탐지한 고위험 공격자 IP를 방화벽이나 라우터의 Blackhole/ACL에 동적 등록하도록 API(REST, BGP Flowspec) 신호 전송.
* **SIEM / 로그 관리 시스템 연동:** CEF, LEEF, JSON, Syslog 표준 포맷 지원. 단, 대량의 Raw 로그로 인해 SIEM 라이선스 비용이 폭증하는 것을 막기 위해 **중복 경보 압축(Aggregation) 및 필터링 전송** 기능 제공.
* **SOAR 연동 (Playbook 자동화):** OpenAPI(RESTful)를 전면 개방하여, SOAR에서 공격 판단 시 IPS에 즉시 차단 정책(IP, URL, 시그니처)을 푸시(Push)하고 패킷 덤프(PCAP)를 자동 수집할 수 있도록 지원.
* **CTI (사이버 위협 인텔리전스) 연동:** STIX/TAXII 2.1 표준 지원. 국정원(NCTI), KISA(C-TAS), 금융보안원 및 글로벌 상용 위협 피드와 실시간 동기화.

---

## 4. 비기능적 요구사항 (성능, 가용성, 컴플라이언스)

### 4.1 고가용성(HA) 및 무중단 아키텍처 (물리 장비 대체 핵심)
* **Bypass NIC 완벽 호환:** 서버 전원 장애, OS 커널 패닉, IPS 데몬 크래시 발생 시 밀리초(ms) 단위로 물리 릴레이가 작동해 트래픽을 통과시키는 하드웨어 Watchdog 연동.
* **Active-Active / Active-Standby 클러스터링:** 상태 정보(TCP 세션 테이블, 차단 목록)를 노드 간 실시간 동기화하여 비대칭 라우팅(Asymmetric Routing) 환경에서도 정확한 탐지 보장.
* **무중단 라이브 업데이트 (Zero-downtime Reload):** 시그니처 룰셋 업데이트나 엔진 패치 시 패킷 유실이나 세션 끊김 없이 워커 스레드만 교체(Hot-Swap)하는 구조.
* **리소스 임계치 기반 Auto-Bypass:** 트래픽 폭주로 CPU 사용률이 90%를 초과하거나 처리 지연(Latency)이 임계치를 넘을 경우, 우선순위가 낮은 L7 검사 룰을 일시 생략하고 L3/L4 핵심 방어만 유지하는 **적응형 품질 제어(Adaptive QoS)** 탑재.

### 4.2 공공기관 및 기업 컴플라이언스 충족
* **인증 요건 설계 반영:**
  * **CC인증 (EAL4 이상) / 보안기능확인서:** 국가·공공기관 도입을 위한 필수 요건으로, 보안 감사 로그 생성, 관리자 권한 분리(RBAC), 자체 보호 기능(무결성 검증), 안전한 세션 관리 등 국가용 보안요구사항(V3.0)을 설계 단계부터 반영.
  * **KCMVP (암호모듈검증):** 관리 콘솔 통신(HTTPS/SSH), 로그 암호화 전송, 설정 파일 암호화 저장 시 국정원 검증필 암호모듈 탑재.
* **감사 및 포렌식(Forensics):**
  * 공격 탐지 순간의 전후 패킷(Pre/Post Attack Packet)을 자동 캡처하여 **PCAP 파일로 저장**하는 Ring-Buffer 기반 타임머신 기능(침해사고 조사 및 법적 증거 확보용).

---

## 5. 기술 스택(Tech Stack) 제안

| 구분 | 구성 요소 | 권장 기술 스택 | 선정 사유 |
| :--- | :--- | :--- | :--- |
| **Data Plane** | 패킷 캡처 및 커널 바이패스 | **eBPF/XDP**, **DPDK**, AF_XDP | 물리 장비(ASIC/FPGA)를 대체할 수 있는 초고속 Zero-copy 패킷 처리 |
| **Core Engine** | DPI 및 스트림 분석 엔진 | **Rust** 또는 **C/C++ (C++20)** | 메모리 안전성(Rust) 확보 및 가비지 컬렉션(GC) 없는 극한의 성능 구현 |
| **Pattern Match** | 다중 패턴 매칭 가속기 | **Vectorscan (Hyperscan 포크)** | SIMD(AVX2/AVX-512, NEON) 명령어를 활용한 수만 개 정규표현식 동시 매칭 |
| **AI / Analytics** | 이상 행위 탐지 엔진 | **Python (PyTorch/ONNX Runtime)** | 학습은 Python으로 수행하고, 추론은 C++/Rust 내장 ONNX로 고속 처리 |
| **Control Plane** | 중앙 관리 서버 & API | **Go (Golang)**, gRPC, REST API | 수백 대의 센서 노드를 관리하기 위한 높은 동시성 및 마이크로서비스 친화성 |
| **Storage/DB** | 정책/자산 DB 및 로그 저장소 | **PostgreSQL**, **ClickHouse** | 초당 수십만 건의 보안 이벤트 로그를 실시간 인덱싱하고 고속 쿼리하기 위함 |
| **Frontend** | 통합 보안 관제 UI (EMS) | **React (TypeScript)**, WebSocket, ECharts | 실시간 위협 맵, 트래픽 토폴로지, 다크모드 기반 SOC 관제 대시보드 구현 |

---

## 6. 단계별 개발 로드맵 (Development Roadmap)

총 18개월(4단계) 기준의 마일스톤을 제안합니다.

* **Phase 1: 코어 패킷 엔진 및 프로토타이핑 (1~4개월)**
  * DPDK 및 eBPF/XDP 기반 하이브리드 패킷 파이프라인 구축.
  * 기본 L2 Bridge(In-line) 포워딩, Bypass NIC 연동, L3/L4 Stateless/Stateful 필터링 구현.
  * 10Gbps 환경에서의 Line-rate 패킷 처리 성능 검증(RFC 2544 벤치마크).
* **Phase 2: DPI 엔진 고도화 및 중앙 관리 시스템(EMS) 구축 (5~9개월)**
  * TCP 재조합, 주요 L7 프로토콜 파서(HTTP, DNS, TLS 등), Vectorscan 기반 시그니처 매칭 엔진 결합.
  * 웹 기반 중앙 관리 콘솔(정책 배포, 실시간 대시보드, PCAP 다운로드) 및 SIEM/SOAR 연동 API 개발.
* **Phase 3: 지능형 탐지(AI), 고가용성(HA) 및 안정화 (10~14개월)**
  * JA3/JA4 암호화 트래픽 분석, 머신러닝 기반 이상 트래픽(DDoS/Beaconing) 탐지 모듈 탑재.
  * Active-Active HA 클러스터링, 무중단 룰 업데이트, Shadow 모드 등 엔터프라이즈 운영 기능 완성.
  * 실제 기업/기관 미러링 트래픽(TAP)을 활용한 대규모 필드 테스트(PoC) 및 오탐 튜닝.
* **Phase 4: 보안 인증 획득 및 상용화/패키징 (15~18개월)**
  * KCMVP 암호모듈 결합 및 보안기능확인서 / GS인증 / CC인증 평가 진행.
  * 다양한 배포 형태 지원 패키징: 베어메탈 설치용 ISO(Hardened Linux OS 포함), 가상화(VMware/KVM) 이미지, 클라우드/쿠버네티스용 컨테이너(DaemonSet) 버전 출시.

---

## 7. 기대 효과 및 차별화 포인트 (도입 설득 논리)

1. **TCO(총소유비용)의 획기적 절감:** 벤더 종속적인 고가의 전용 하드웨어 대신 범용 고성능 서버(x86)를 활용하며, 트래픽 증가 시 소프트웨어 라이선스와 범용 서버만 유연하게 증설(Scale-out) 가능.
2. **방화벽 및 내부 보안 장비의 생존성 극대화:** 1차 방어선(Pre-Firewall)에서 eBPF/XDP를 통해 대규모 볼륨 공격과 불필요한 스캐닝 패킷을 커널 진입 전에 소멸시켜, 후단에 위치한 고가의 차세대 방화벽(NGFW) 및 서버 자원을 완벽히 보호.
3. **보안 아키텍처 유연성 확보:** 온프레미스 물리 네트워크의 1차 관문뿐만 아니라, 동일한 소프트웨어 엔진을 프라이빗 클라우드, 퍼블릭 클라우드(VPC Ingress)에 일관된 정책으로 배포할 수 있는 **하이브리드 메시(Mesh) 방어 체계** 완성.
