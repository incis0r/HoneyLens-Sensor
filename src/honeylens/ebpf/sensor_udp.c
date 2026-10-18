/* =========================================================================
 * sensor_udp.c — Enhanced UDP eBPF Sensor
 * =========================================================================
 * Captures UDP packets with additional inspection:
 *   - TTL for OS fingerprinting
 *   - Payload first-256-byte sample for protocol detection in userspace
 *     (was 16; bumped 2026-05-07 to capture full DNS query / first DTLS record)
 *   - DNS flag detection (port 53 + header bits)
 *   - IP TOS / DSCP for traffic classification
 * ========================================================================= */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

struct event_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 pkt_len;
    /* --- Deep inspection fields --- */
    u8  ttl;
    u8  ip_tos;
    u16 udp_len;            /* UDP length header field */
    u16 ip_id;
    u16 ip_frag_off;
    u8  payload_sample[256]; /* first 256 bytes of UDP payload */
    u16 payload_len;         /* actual bytes captured (0..256) */
    u8  is_dns;             /* heuristic: dst_port==53 or src_port==53 */
};

BPF_PERF_OUTPUT(events);

/* event_t too large for BPF stack with 256-byte payload; use per-CPU array. */
BPF_PERCPU_ARRAY(event_scratch, struct event_t, 1);

int packet_filter(struct __sk_buff *skb) {
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return 0;

    struct iphdr ip;
    bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip));

    if (ip.protocol != IPPROTO_UDP)
        return 0;

    struct udphdr udp;
    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip), &udp, sizeof(udp));

    u32 zero = 0;
    struct event_t *evp = event_scratch.lookup(&zero);
    if (!evp)
        return 0;
    __builtin_memset(evp, 0, sizeof(*evp));

    /* --- Core fields --- */
    evp->src_ip   = ip.saddr;
    evp->dst_ip   = ip.daddr;
    evp->src_port = udp.source;
    evp->dst_port = udp.dest;
    evp->pkt_len  = skb->len;

    /* --- Deep inspection --- */
    evp->ttl         = ip.ttl;
    evp->ip_tos      = ip.tos;
    evp->udp_len     = udp.len;
    evp->ip_id       = ip.id;
    evp->ip_frag_off = ip.frag_off;

    /* DNS heuristic */
    u16 sp = __constant_ntohs(udp.source);
    u16 dp = __constant_ntohs(udp.dest);
    evp->is_dns = (sp == 53 || dp == 53) ? 1 : 0;

    /* --- Payload sample (first 256 bytes) --- */
    u32 payload_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    u32 total_len   = skb->len;
    u32 avail       = 0;

    if (total_len > payload_off)
        avail = total_len - payload_off;

    if (avail > 256)
        avail = 256;

    evp->payload_len = avail;

    if (avail > 0) {
        bpf_skb_load_bytes(skb, payload_off, evp->payload_sample, 256);
    }

    events.perf_submit(skb, evp, sizeof(*evp));
    return -1;
}
