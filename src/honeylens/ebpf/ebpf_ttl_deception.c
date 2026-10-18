/*
 * ebpf_ttl_deception.c — TC egress BPF classifier
 * =================================================
 * Rewrites IP TTL and TCP window on outbound honeypot traffic to mimic
 * the target OS fingerprint (Windows, PLC, etc.).
 *
 * Loaded by: ebpf_ttl_loader.py (via BCC)
 * Hook:      TC egress on the capture interface
 *
 * CHECKSUM HANDLING:
 * On modern NICs with TX checksum offload (CHECKSUM_PARTIAL), the kernel
 * leaves tcp->check as a partial pseudo-header checksum — the NIC computes
 * the rest in hardware. When we modify IP TTL (which is NOT in the TCP
 * pseudo-header), the TCP checksum is unaffected. When we modify the TCP
 * window (which IS in the TCP header), we must use bpf_l4_csum_replace
 * WITHOUT BPF_F_PSEUDO_HDR — because the pseudo-header portion is already
 * correct and only the header/payload portion needs updating.
 *
 * The key insight: BPF_F_PSEUDO_HDR means "this field is in the pseudo-header,
 * adjust accordingly". TCP window is NOT in the pseudo-header, so we must NOT
 * set that flag. Setting it causes a double-adjustment that corrupts the
 * partial checksum.
 *
 * Kernel requirements: 5.14+ (Rocky 9), BCC
 */

#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* ── OS fingerprint profile ──────────────────────────────────────────── */
struct os_profile {
    __u8  ttl;
    __u16 tcp_window;
    __u8  tcp_wscale;
    __u8  profile_id;
};

/* ── BPF maps ────────────────────────────────────────────────────────── */
BPF_HASH(port_profiles, u16, struct os_profile, 64);

/* Stats: 0=inspected, 1=ttl_rewritten, 2=synack_window, 3=errors */
BPF_ARRAY(stats, u64, 4);

static __always_inline void stat_inc(u32 idx)
{
    u64 *cnt = stats.lookup(&idx);
    if (cnt) (*cnt)++;
}

/* ── TC egress entry point ───────────────────────────────────────────── */
int ttl_deception(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* ── Parse Ethernet ── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    /* ── Parse IP ── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return TC_ACT_OK;

    /* ── Parse TCP ── */
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    /* ── Lookup source port ── */
    u16 sport = ntohs(tcp->source);
    struct os_profile *prof = port_profiles.lookup(&sport);
    if (!prof)
        return TC_ACT_OK;

    stat_inc(0);

    /* ── Byte offsets from skb start ──────────────────────────────── */
    __u32 ip_off       = sizeof(struct ethhdr);     /* 14 */
    __u32 ttl_off      = ip_off + 8;                /* iphdr.ttl */
    __u32 ip_csum_off  = ip_off + 10;               /* iphdr.check */
    __u32 tcp_off      = ip_off + ip_hdr_len;
    __u32 win_off      = tcp_off + 14;              /* tcphdr.window */
    __u32 tcp_csum_off = tcp_off + 16;              /* tcphdr.check */

    /* Save values before any skb modification */
    __u8  old_ttl    = ip->ttl;
    __u16 old_win    = tcp->window;
    __u8  is_syn_ack = (tcp->syn == 1 && tcp->ack == 1);

    /* ── Rewrite TTL ──────────────────────────────────────────────
     *
     * TTL is in the IP header only. It is NOT part of the TCP pseudo-header.
     * Therefore:
     *   - Update IP checksum via bpf_l3_csum_replace  (required)
     *   - TCP checksum is NOT affected by TTL change   (do nothing)
     */
    if (prof->ttl > 0 && old_ttl != prof->ttl) {
        __u8 new_ttl = prof->ttl;

        /* bpf_l3_csum_replace works on 16-bit aligned words.
         * TTL + Protocol occupy bytes 8-9 of the IP header.
         * We replace the full 16-bit word to ensure correct alignment. */
        __u8 proto = ip->protocol;  /* save — same word */
        __u16 old_ttl_proto = ((__u16)old_ttl << 8) | proto;
        __u16 new_ttl_proto = ((__u16)new_ttl << 8) | proto;

        int ret = bpf_l3_csum_replace(skb, ip_csum_off,
                                       htons(old_ttl_proto),
                                       htons(new_ttl_proto), 2);
        if (ret < 0) {
            stat_inc(3);
            return TC_ACT_OK;
        }

        ret = bpf_skb_store_bytes(skb, ttl_off, &new_ttl, 1, 0);
        if (ret < 0) {
            stat_inc(3);
            return TC_ACT_OK;
        }

        stat_inc(1);
    }

    /* ── Rewrite TCP Window on SYN-ACK only ──────────────────────
     *
     * TCP window IS in the TCP header (not the pseudo-header).
     * We must update the TCP checksum when changing it.
     *
     * CRITICAL: Do NOT use BPF_F_PSEUDO_HDR flag here.
     * BPF_F_PSEUDO_HDR tells the helper that the changed field is part
     * of the pseudo-header (src_ip, dst_ip, protocol, length). The TCP
     * window is NOT in the pseudo-header — it's in the TCP header proper.
     * Using BPF_F_PSEUDO_HDR here causes an incorrect adjustment that
     * corrupts the checksum, especially when TX checksum offload is active
     * (CHECKSUM_PARTIAL mode where tcp->check holds only the pseudo-header
     * checksum and the NIC finishes it).
     *
     * With flag=2 (size only, no pseudo-header), bpf_l4_csum_replace
     * does a straightforward incremental update:
     *   new_csum = old_csum - old_val + new_val
     * This works correctly in both full-checksum and partial-checksum modes.
     */
    if (prof->tcp_window > 0 && is_syn_ack) {
        __u16 new_win = htons(prof->tcp_window);

        if (old_win != new_win) {
            int ret = bpf_l4_csum_replace(skb, tcp_csum_off,
                                           old_win, new_win,
                                           2);  /* size=2, NO BPF_F_PSEUDO_HDR */
            if (ret < 0) {
                stat_inc(3);
                return TC_ACT_OK;
            }

            ret = bpf_skb_store_bytes(skb, win_off, &new_win, 2, 0);
            if (ret < 0) {
                stat_inc(3);
                return TC_ACT_OK;
            }

            stat_inc(2);
        }
    }

    return TC_ACT_OK;
}
