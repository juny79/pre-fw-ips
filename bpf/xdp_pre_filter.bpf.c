// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "include/common_maps.h"

// 1. AF_XDP 소켓 맵 (User-space Rust 워커 스레드와 Zero-copy 연결)
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64); // 최대 64개 CPU 코어(RX Queue) 지원
} xsks_map SEC(".maps");

// 2. 실시간 차단 IP LPM Trie 맵 (SOAR 및 DPI 엔진이 동적 업데이트)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key);
    __type(value, struct block_entry_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 2000000); // 200만 개 악성 IP/CIDR 수용
} blacklist_map SEC(".maps");

// 3. 세션 상태 및 Elephant Flow Bypass 맵 (Per-CPU Hash로 Lock 제거)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_state_val);
    __uint(max_entries, 1000000);
} flow_map SEC(".maps");

// 인라인 반대편 포트 번호 매핑 (예: eth0(ifindex 2) <-> eth1(ifindex 3))
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 16);
} tx_port_map SEC(".maps");

SEC("xdp")
int xdp_ips_FirstLine(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 rx_queue_idx = ctx->rx_queue_index;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP; // 비정상 프레임 즉시 폐기

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;

    // [Step 1] LPM Trie 기반 초고속 위협 IP 조회 (방화벽 도달 전 1차 소멸)
    struct lpm_ip_key lpm_key = { .prefixlen = 32 };
    __builtin_memcpy(lpm_key.ip, &iph->saddr, 4);

    struct block_entry_val *blk = bpf_map_lookup_elem(&blacklist_map, &lpm_key);
    if (blk) {
        __u64 now = bpf_ktime_get_ns();
        if (blk->expire_ts == 0 || now < blk->expire_ts) {
            __sync_fetch_and_add(&blk->hit_packets, 1);
            __sync_fetch_and_add(&blk->hit_bytes, (data_end - data));
            if (blk->action == 1)
                return XDP_DROP; // 나노초 단위 즉시 폐기 (CPU 소모 0)
        }
    }

    // [Step 2] 5-Tuple 추출 및 Elephant Flow Fast-Bypass 확인
    struct flow_key fkey = {0};
    __builtin_memcpy(fkey.src_ip, &iph->saddr, 4);
    __builtin_memcpy(fkey.dst_ip, &iph->daddr, 4);
    fkey.proto = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end) return XDP_DROP;
        
        // 비정상 TCP Flag (예: SYN+FIN 동시 설정 등 정찰 스캐닝) 즉시 차단
        if ((tcph->syn && tcph->fin) || (tcph->syn && tcph->rst))
            return XDP_DROP;

        fkey.src_port = tcph->source;
        fkey.dst_port = tcph->dest;
    }

    struct flow_state_val *fstate = bpf_map_lookup_elem(&flow_map, &fkey);
    if (fstate && fstate->bypass_dpi == 1) {
        fstate->last_seen_ns = bpf_ktime_get_ns();
        // DPI 엔진이 안전하다고 마킹한 대용량 세션은 유저 공간으로 올리지 않고 반대편 NIC로 즉시 포워딩
        return bpf_redirect_map(&tx_port_map, ctx->ingress_ifindex, XDP_PASS);
    }

    // [Step 3] 정밀 L7 검사를 위해 해당 CPU 코어에 바인딩된 User-space AF_XDP 소켓으로 Zero-copy 전달
    if (bpf_map_lookup_elem(&xsks_map, &rx_queue_idx))
        return bpf_redirect_map(&xsks_map, rx_queue_idx, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
