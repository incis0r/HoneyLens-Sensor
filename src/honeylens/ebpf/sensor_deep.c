/* =========================================================================
 * sensor_deep.c — Deep Packet Inspection eBPF Sensor
 * =========================================================================
 * Captures non-TCP/UDP traffic that the other sensors miss:
 *   - ICMP (ping sweeps, unreachable probes, timestamp requests)
 *   - IP protocol anomalies (GRE, SCTP, etc.)
 *   - Fragmented packets (often used to evade IDS)
 *
 * This is a supplementary sensor — run alongside sensor_tcp.c and
 * sensor_udp.c for complete coverage.
 * ========================================================================= */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* ICMP type constants */
#define ICMP_ECHO_REPLY       0
#define ICMP_DEST_UNREACHABLE 3
#define ICMP_ECHO_REQUEST     8
#define ICMP_TIMESTAMP        13
#define ICMP_TIMESTAMP_REPLY  14
#define ICMP_ADDR_MASK        17

/* Classification labels */
#define DEEP_ICMP_ECHO        1
#define DEEP_ICMP_SWEEP       2   /* echo req with TTL patterns */
#define DEEP_ICMP_TIMESTAMP   3
#define DEEP_ICMP_UNREACHABLE 4
#define DEEP_ICMP_OTHER       5
#define DEEP_FRAG             6   /* fragmented IP packet */
#define DEEP_PROTO_ANOMALY    7   /* unusual IP protocol number */
#define DEEP_ICMP_ADDR_MASK   8

struct deep_event_t {
    u32 src_ip;
    u32 dst_ip;
    u8  ip_protocol;
    u8  ttl;
    u8  ip_tos;
    u16 ip_id;
    u16 ip_frag_off;
    u32 pkt_len;
    u8  classification;
    /* ICMP-specific */
    u8  icmp_type;
    u8  icmp_code;
    /* Payload sample — bumped 2026-05-07 from 16 → 256 bytes for deeper DPI */
    u8  payload_sample[256];
    u16 payload_len;
};

BPF_PERF_OUTPUT(events);

/* Per-CPU scratch for the now-larger event_t. */
BPF_PERCPU_ARRAY(event_scratch, struct deep_event_t, 1);

int packet_filter(struct __sk_buff *skb) {
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return 0;

    struct iphdr ip;
    bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip));

    /* Skip TCP and UDP — those are handled by the other sensors */
    if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP)
        return 0;

    u32 zero = 0;
    struct deep_event_t *evp = event_scratch.lookup(&zero);
    if (!evp)
        return 0;
    __builtin_memset(evp, 0, sizeof(*evp));

    evp->src_ip      = ip.saddr;
    evp->dst_ip      = ip.daddr;
    evp->ip_protocol = ip.protocol;
    evp->ttl         = ip.ttl;
    evp->ip_tos      = ip.tos;
    evp->ip_id       = ip.id;
    evp->ip_frag_off = ip.frag_off;
    evp->pkt_len     = skb->len;

    /* --- Check for fragmentation --- */
    u16 frag = __constant_ntohs(ip.frag_off);
    if ((frag & 0x1FFF) != 0 || (frag & 0x2000)) {
        evp->classification = DEEP_FRAG;
        /* Still try to grab payload sample from fragment */
        goto sample_payload;
    }

    /* --- ICMP handling --- */
    if (ip.protocol == IPPROTO_ICMP) {
        u32 icmp_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
        u8 icmp_type = 0, icmp_code = 0;

        if (icmp_off + 2 <= skb->len) {
            bpf_skb_load_bytes(skb, icmp_off,     &icmp_type, 1);
            bpf_skb_load_bytes(skb, icmp_off + 1, &icmp_code, 1);
        }

        evp->icmp_type = icmp_type;
        evp->icmp_code = icmp_code;

        if (icmp_type == ICMP_ECHO_REQUEST || icmp_type == ICMP_ECHO_REPLY) {
            /* Heuristic: TTL=1 or TTL=64 with small payload => possible sweep */
            if (ip.ttl <= 2 || skb->len <= 60)
                evp->classification = DEEP_ICMP_SWEEP;
            else
                evp->classification = DEEP_ICMP_ECHO;
        }
        else if (icmp_type == ICMP_TIMESTAMP || icmp_type == ICMP_TIMESTAMP_REPLY)
            evp->classification = DEEP_ICMP_TIMESTAMP;
        else if (icmp_type == ICMP_DEST_UNREACHABLE)
            evp->classification = DEEP_ICMP_UNREACHABLE;
        else if (icmp_type == ICMP_ADDR_MASK)
            evp->classification = DEEP_ICMP_ADDR_MASK;
        else
            evp->classification = DEEP_ICMP_OTHER;

        goto sample_payload;
    }

    /* --- Anything else is a protocol anomaly (GRE, SCTP, IGMP, ...) --- */
    evp->classification = DEEP_PROTO_ANOMALY;

sample_payload:
    ;  /* label needs a statement */
    u32 hdr_len     = sizeof(struct ethhdr) + (ip.ihl * 4);
    u32 total_len   = skb->len;
    u32 avail       = 0;

    if (total_len > hdr_len)
        avail = total_len - hdr_len;
    if (avail > 256)
        avail = 256;

    evp->payload_len = avail;
    if (avail > 0) {
        bpf_skb_load_bytes(skb, hdr_len, evp->payload_sample, 256);
    }

    events.perf_submit(skb, evp, sizeof(*evp));
    return -1;
}
