# 📂 Pre-Firewall S/W IDS/IPS 기술 보고서 패키지 (`v1.0.0`)

| 항목 | 내용 |
| :--- | :--- |
| **문서 버전** | `v1.0.0` (Baseline Release) |
| **작성 일자** | 2026-11-19 |
| **대상 독자** | CISO, 기업/공공기관 보안팀(SOC/CERT), 네트워크/보안 아키텍트, 코어 엔진 개발팀 |
| **문서 상태** | Approved (Baseline) |

---

## 📑 보고서 구성 목차

1. **[01_Master_Plan_Report.md](./01_Master_Plan_Report.md)**
   * **문서명:** 차세대 Pre-Firewall 소프트웨어 기반 IDS/IPS 개발 종합기획서
   * **주요 내용:** 개발 배경 및 목표, 배치 토폴로지 개요, 핵심 기능 정의(오탐 최소화, SOC 생태계 연동), 고가용성/컴플라이언스 요건, 기술 스택, 18개월 개발 로드맵, TCO 절감 기대효과
2. **[02_Technical_Architecture_Design.md](./02_Technical_Architecture_Design.md)**
   * **문서명:** 전사 보안 아키텍처 기반 Pre-Firewall S/W IDS/IPS 상세 기술 아키텍처 설계서
   * **주요 내용:** 전사 보안 시스템(NGFW, SIEM, SOAR, CTI) 역할 분담, 3-Tier Zero-Copy 데이터 플레인(XDP + AF_XDP/DPDK), 6단계 DPI 파이프라인, 비복호화 TLS 1.3/QUIC 분석(JA4), 비동기 AI 추론(ONNX) 및 PCAP 타임머신, RCU 무중단 리로드, 4단계 Fail-Safe, 10G/40G/100G 하드웨어 사이징
3. **[03_DB_Schema_Rule_and_API_Spec.md](./03_DB_Schema_Rule_and_API_Spec.md)**
   * **문서명:** 3계층 데이터베이스 스키마, 확장 룰 문법 및 외부 연동 API 상세 명세서
   * **주요 내용:** Tier-0(eBPF Maps C Struct), Tier-1(PostgreSQL 16 DDL), Tier-2(ClickHouse OLAP DDL), Suricata 호환 차세대 확장 룰 문법, OpenAPI 3.0 REST API 엔드포인트 및 JSON 페이로드 명세
4. **[04_Core_Engine_Prototype_and_Verification_Plan.md](./04_Core_Engine_Prototype_and_Verification_Plan.md)**
   * **문서명:** 코어 엔진 프로토타입 구현 가이드 및 성능·보안인증 검증 계획서
   * **주요 내용:** Monorepo 코드 구조, eBPF/XDP 커널 필터 코드 해설, Rust RCU 워커 코드 해설, Cisco TRex 벤치마크 KPI, Bypass NIC Fail-Open 테스트, 우회 공격(Evasion) 방어 시나리오, 국가용 보안요구사항(V3.0) 매핑표
