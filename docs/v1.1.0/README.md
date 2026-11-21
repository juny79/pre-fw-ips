# 📂 Pre-Firewall S/W IDS/IPS 기술 보고서 패키지 (`v1.1.0`)

| 항목 | 내용 |
| :--- | :--- |
| **문서 버전** | `v1.1.0` (Full-Stack SOC EMS Server & Architecture Telemetry Release) |
| **작성 일자** | 2026-11-21 |
| **대상 독자** | CISO, 기업/공공기관 보안팀(SOC/CERT), 백엔드/프론트엔드 관제 개발팀 |
| **문서 상태** | Approved (Release `v1.1.0`) |

---

## 📑 `v1.1.0` 신규 추가 및 고도화 보고서 목차

* **[05_SOC_EMS_Backend_and_Dashboard_Guide.md](./05_SOC_EMS_Backend_and_Dashboard_Guide.md)** (`IPS-DOC-2026-V1.1-05`)
  * **문서명:** 전사 보안 아키텍처 퍼포먼스 검증용 SOC 통합 보안 관제(EMS) 백엔드 서버 및 웹 대시보드 구축 보고서
  * **주요 내용:**
    1. 전체 보안 아키텍처 5단계(WAN 라우터 $\rightarrow$ Pre-Firewall IDS/IPS $\rightarrow$ 차세대 방화벽 $\rightarrow$ 코어 스위치/TAP $\rightarrow$ 내부 서버군 & SIEM/SOAR/CTI) 실시간 퍼포먼스 모델링 설계
    2. 3계층 폴리글랏 저장소(Tier-0 eBPF LPM Trie 인메모리 맵 + Tier-1 SQLite/PostgreSQL 컨트롤 플레인 + Tier-2 실시간 시계열 텔레메트리) 백엔드(`ems-server/app.py`) 구축 과정
    3. KCMVP 체인형 HMAC-SHA256 보안 감사 추적 및 PCAP 타임머신 Hex/ASCII 포렌식 엔진 구현 명세
    4. 웹 대시보드(`http://127.0.0.1:8090`) 구동 및 API 테스트 가이드

> 💡 **이전 버전(`v1.0.0`) 기본 설계 보고서 참조:**
> * [01. 종합기획서](../v1.0.0/01_Master_Plan_Report.md)
> * [02. 상세 기술 아키텍처 설계서](../v1.0.0/02_Technical_Architecture_Design.md)
> * [03. DB 스키마, 룰 문법 및 API 명세서](../v1.0.0/03_DB_Schema_Rule_and_API_Spec.md)
> * [04. 코어 엔진 프로토타입 및 검증/인증 계획서](../v1.0.0/04_Core_Engine_Prototype_and_Verification_Plan.md)
