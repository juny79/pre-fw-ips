# 📑 문서 및 아키텍처 버전 이력 (CHANGELOG)

본 문서는 **차세대 Pre-Firewall S/W IDS/IPS 개발 프로젝트(`pre-fw-ips`)**의 기획서, 상세 기술 아키텍처 설계서, DB/API 명세서 및 검증 계획서의 버전별 개정 이력을 관리합니다.

---

## [v1.0.0] - 2026-11-19 (Initial Baseline Release)

### ✨ 신규 작성 (Added)
* **`docs/v1.0.0/01_Master_Plan_Report.md` (종합기획서 v1.0.0)**
  * 방화벽 전단(1차 방어선) 물리 장비 대체 배경 및 TCO 절감 기대 효과 수립
  * 3-Tier 패킷 처리 아키텍처(eBPF/XDP + DPDK/AF_XDP + 비동기 AI) 개념 정의
  * 기업/공공기관 보안팀(SOC) 요구사항(Shadow 모드, Asset Context 연동, PCAP 타임머신) 및 18개월 로드맵 수립
* **`docs/v1.0.0/02_Technical_Architecture_Design.md` (상세 기술 아키텍처 설계서 v1.0.0)**
  * 전사 보안 생태계(NGFW, SIEM, SOAR, CTI, BGP Router) 연동 토폴로지 상세 설계
  * Symmetric RSS, NUMA Locality, 1GB Hugepages 기반 Zero-copy 데이터 플레인 설계
  * 6단계 인라인 DPI 파이프라인(Target-based TCP 재조합, Rust L7 파서, Vectorscan SIMD 매칭, JA3/JA4 암호화 분석) 설계
  * RCU(Read-Copy-Update) 기반 무중단 룰 리로드 및 4단계 Fail-Safe(Hardware Bypass NIC Watchdog) 메커니즘 정의
  * 10G / 40G / 100G 센서별 COTS 하드웨어 사이징 기준표 수립
* **`docs/v1.0.0/03_DB_Schema_Rule_and_API_Spec.md` (데이터베이스 스키마, 룰 문법 및 API 명세서 v1.0.0)**
  * Tier-0(eBPF Map C 구조체), Tier-1(PostgreSQL 16 DDL), Tier-2(ClickHouse MergeTree DDL) 3계층 폴리글랏 저장소 스키마 명세
  * Suricata/Snort 3 호환 차세대 확장 룰 문법(`context.target_tech`, `xdp.offload_block`, `forensic.pcap`, `ai.beacon_score`) 정의
  * SOAR 실시간 차단 위임, SIEM 압축 경보 스트리밍, Shadow 모드 평가 리포트용 OpenAPI 3.0 JSON 스키마 명세
* **`docs/v1.0.0/04_Core_Engine_Prototype_and_Verification_Plan.md` (코어 엔진 프로토타입 및 검증/인증 계획서 v1.0.0)**
  * C(eBPF/XDP) 및 Rust(`ArcSwap` RCU + DPI Worker) 프로토타입 스켈레톤 코드 구현 및 연동 구조 문서화
  * Cisco TRex 기반 성능 벤치마크(Throughput, Latency, CPS, DDoS 생존성) 합격 기준(KPI) 수립
  * Bypass NIC 장애 복구(Fail-Open) 및 Pytbull/우회 공격(Evasion) 방어 테스트 시나리오 정의
  * 국가용 보안요구사항(침입방지시스템 V3.0), 보안기능확인서 및 KCMVP 암호모듈 대응 매핑표 작성
