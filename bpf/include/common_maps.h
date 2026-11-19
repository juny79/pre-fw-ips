/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __COMMON_MAPS_H
#define __COMMON_MAPS_H

#include <linux/types.h>

// 1. LPM Trie 기반 실시간 차단 IP/대역 맵 (BPF_MAP_TYPE_LPM_TRIE)
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

#endif /* __COMMON_MAPS_H */
