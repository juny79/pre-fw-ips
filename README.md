# 🛡️ Pre-Firewall Next-Gen S/W IDS/IPS (`pre-fw-ips`)

> **기업 및 공공기관 1차 방어선(Pre-Firewall) 물리 어플라이언스 대체를 위한 차세대 소프트웨어 정의(Software-Defined) IDS/IPS 프로젝트**  
> **Current Version:** `v1.0.0` (2026-11-19)

---

## 📌 프로젝트 개요

본 레포지토리는 차세대 방화벽(NGFW) 전단(WAN 라우터와 방화벽 사이)에 배치되어 대규모 볼륨 공격(DDoS, SYN Flood, 스캐닝) 및 L7 애플리케이션 취약점 공격을 1차적으로 정밀 필터링(Pre-filtering)하는 **eBPF/XDP 및 Rust(AF_XDP + Vectorscan) 기반 초고속 소프트웨어 IDS/IPS**의 종합 기획, 상세 기술 아키텍처, 데이터베이스/API 명세 및 코어 엔진 프로토타입을 포함합니다.

---

## 📚 버전별 기술 보고서 및 설계 문서 (`docs/`)

모든 기획 및 기술 설계 보고서는 버전별로 형상 관리되며 [`docs/`](file:///C:/Users/user/.gemini/antigravity/scratch/pre-fw-ips/docs) 디렉터리 아래에 체계화되어 있습니다.

* **[변경 이력 (CHANGELOG.md)](file:///C:/Users/user/.gemini/antigravity/scratch/pre-fw-ips/docs/CHANGELOG.md)**
* **[최신 릴리스: `v1.0.0` 보고서 인덱스](file:///C:/Users/user/.gemini/antigravity/scratch/pre-fw-ips/docs/v1.0.0/README.md)**
  1. **[01. 종합기획서 (Master Plan Report)](file:///C:/Users/user/.gemini/antigravity/scratch/pre-fw-ips/docs/v1.0.0/01_Master_Plan_Report.md)**
     * 개발 배경, 물리 장비 대비 TCO 절감 논리, 3-Tier 패킷 아키텍처 개요, 18개월 로드맵
  2. **[02. 상세 기술 아키텍처 설계서 (Technical Architecture Design)](file:///C:/Users/user/.gemini/antigravity/scratch/pre-fw-ips/docs/v1.0.0/02_Technical_Architecture_Design.md)**
     * 전사 보안 시스템(NGFW, SIEM, SOAR, CTI) 연동 토폴로지, XDP/AF_XDP Zero-copy 파이프라인, 6단계 DPI 엔진, RCU 무중단 리로드, 4단계 Fail-Safe(Bypass NIC) 설계
  3. **[03. DB 스키마, 룰 문법 및 API 명세서 (DB Schema, Rules & API Spec)](file:///C:/Users/user/.gemini/antigravity/scratch/pre-fw-ips/docs/v1.0.0/03_DB_Schema_Rule_and_API_Spec.md)**
     * Tier-0(eBPF Map), Tier-1(PostgreSQL), Tier-2(ClickHouse) DDL 스키마, 확장 Snort/Suricata 룰 문법, OpenAPI 3.0(SOAR/SIEM/Shadow 모드) 명세
  4. **[04. 코어 엔진 프로토타입 및 검증/인증 계획서 (Core Prototype & Verification Plan)](file:///C:/Users/user/.gemini/antigravity/scratch/pre-fw-ips/docs/v1.0.0/04_Core_Engine_Prototype_and_Verification_Plan.md)**
     * C(eBPF/XDP) 및 Rust(AF_XDP + RCU) 코어 스켈레톤 구현 설명, Cisco TRex 기반 10G/40G/100G 성능 벤치마크 기준, 우회 공격(Evasion) 테스트, 국가용 보안요구사항 V3.0(보안기능확인서/KCMVP) 매핑표

---

## 🗂️ 디렉터리 구조 (Repository Layout)

```text
pre-fw-ips/
├── README.md
├── Cargo.toml                                  # Rust Workspace 설정
├── docs/                                       # 버전 관리형 공식 보고서 및 설계 문서
│   ├── CHANGELOG.md                            # 문서 및 아키텍처 버전 이력
│   └── v1.0.0/                                 # v1.0.0 Baseline 보고서 패키지
│       ├── README.md
│       ├── 01_Master_Plan_Report.md
│       ├── 02_Technical_Architecture_Design.md
│       ├── 03_DB_Schema_Rule_and_API_Spec.md
│       └── 04_Core_Engine_Prototype_and_Verification_Plan.md
├── bpf/                                        # [Tier 1] eBPF / XDP 커널 프로그램 (C)
│   ├── include/
│   │   └── common_maps.h                       # 커널-유저 공간 공유 구조체
│   └── xdp_pre_filter.bpf.c                    # XDP 초고속 차단 및 AF_XDP 리다이렉트
└── ips-core/                                   # [Tier 2] User-space DPI 인라인 엔진 (Rust)
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        └── engine/
            └── rcu_ruleset.rs                  # RCU 무중단 룰셋 및 인라인 DPI 워커
```
