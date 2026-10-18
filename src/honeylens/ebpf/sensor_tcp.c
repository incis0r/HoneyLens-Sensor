/* =========================================================================
 * sensor_tcp.c — Enhanced TCP eBPF Scan Classifier
 * =========================================================================
 * Captures TCP packets with deeper header inspection:
 *   - Full TCP flag classification (SYN/FIN/NULL/XMAS/ACK/Window scans)
 *   - TTL fingerprinting (OS guessing: 64=Linux, 128=Windows, 255=Cisco)
 *   - TCP window size (zero-window probes are strong scan indicators)
 *   - Payload sample for DPI in userspace:
 *       - Default 256 bytes (was 16 before 2026-05-07 — bumped for
 *         CVE-2026-0300 captive-portal BoF probes)
 *       - Up to 4096 bytes when destination port is in `monitored_ports`
 *         map (Idea 30 Phase 0, 2026-05-16 — preserves exploit-shape
 *         POST bodies that the application-layer parser may lose)
 *   - TCP sequence number (Idea 30 Phase 0 — enables userspace
 *     reassembly/dedup without full kernel-side TCP reassembly)
 *   - Timestamp option detection
 * ========================================================================= */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

/* Scan type constants */
#define SCAN_SYN      1
#define SCAN_FIN      2
#define SCAN_NULL     3
#define SCAN_XMAS     4
#define SCAN_ACK      5
#define SCAN_NORMAL   6
#define SCAN_WINDOW   7   /* ACK with zero window — window scan */
#define SCAN_MAIMON   8   /* FIN+ACK — Maimon scan */

/* Tiered capture depths — must match values accepted by the
 * ebpf_dissection_ports CHECK constraint in setup_db.py.
 *
 * Phase 0.5 history (2026-05-22): DEPTH_FULL was capped at 1 KB on
 * 2026-05-17 to dodge a BPF-verifier rejection ("A call to built-in
 * function 'memset' is not supported"). Investigation after the
 * 2026-05-21 172.104.140.109 incident — where a 2 120-byte exploit
 * POST body landed past the 1 KB ceiling and we couldn't capture it
 * via Phase 0 — confirmed the verifier-memset issue was caused by the
 * earlier `__builtin_memset(evp, 0, sizeof(*evp))` call we used to
 * scrub the per-CPU scratch buffer. That memset was removed entirely
 * back on 2026-05-16; the only stale field is `has_ts_option`, which
 * is now zeroed explicitly. With no whole-struct zero-init, clang no
 * longer emits the libcall and the verifier accepts a 4 KB struct.
 *
 * The cost is one perf_submit per event up to ~4.4 KB (struct size).
 * At ~hundreds of events/sec on the public sensors this is well within
 * the perf-buffer headroom (64 pages × 4 KB × CPUs ≈ MB-class buffer).
 * For un-monitored ports only the 256-byte base tier executes — the
 * extra 3 KB of payload_sample[] beyond the first 1 KB is allocated
 * (in the per-CPU scratch map) but not populated, and the perf_submit
 * still copies the whole struct so wire bytes per event grow. Worth
 * it: we'd rather pay the bytes than miss the body. */
#define DEPTH_BASE   256
#define DEPTH_MID    1024
#define DEPTH_FULL   4096

struct event_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  scan_type;
    u8  tcp_flags;
    u32 pkt_len;
    /* --- Deep inspection fields --- */
    u8  ttl;
    u16 window_size;
    u8  ip_tos;            /* Type-of-Service / DSCP */
    u8  tcp_data_offset;   /* TCP header length in 32-bit words */
    u16 ip_id;             /* IP identification — randomized = modern OS */
    /* --- Idea 30 Phase 0 fields --- */
    u32 tcp_seq;           /* TCP sequence number (host-byte-order) */
    u32 capture_depth;     /* actual depth attempted (256/1024/4096) */
    /* --- Payload + tail fields --- */
    u16 payload_len;       /* actual bytes captured (0..capture_depth) */
    u8  has_ts_option;     /* 1 if TCP timestamp option present */
    u16 ip_frag_off;       /* fragment offset — fragmented scans */
    u8  payload_sample[DEPTH_FULL];  /* up to 4096 bytes of TCP payload */
};

BPF_PERF_OUTPUT(events);

/* event_t is too large for BPF stack with the 4096-byte payload sample;
 * use a per-CPU array as scratch space instead. Single-element map. */
BPF_PERCPU_ARRAY(event_scratch, struct event_t, 1);

/* monitored_ports — populated by userspace from EBPF_DISSECTION_PORTS +
 * the ebpf_dissection_ports DB table. Key is the host-byte-order
 * destination port; value is the capture depth in bytes (must be one
 * of DEPTH_BASE, DEPTH_MID, DEPTH_FULL). Lookup miss => DEPTH_BASE. */
BPF_HASH(monitored_ports, u16, u32, 1024);

int packet_filter(struct __sk_buff *skb) {
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return 0;

    struct iphdr ip;
    bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip));

    if (ip.protocol != IPPROTO_TCP)
        return 0;

    struct tcphdr tcp;
    bpf_skb_load_bytes(skb, sizeof(eth) + sizeof(ip), &tcp, sizeof(tcp));

    /* Use per-CPU map as scratch; struct is too big for stack now. */
    u32 zero = 0;
    struct event_t *evp = event_scratch.lookup(&zero);
    if (!evp)
        return 0;
    /* Note: we deliberately do NOT __builtin_memset the whole struct.
     * On the 4 KB payload_sample[] introduced in Idea 30 Phase 0 the
     * clang lowering emits an actual `memset` libcall which the BPF
     * verifier rejects ("A call to built-in function 'memset' is not
     * supported"). Every field below is set unconditionally except
     * has_ts_option, which is initialised to 0 explicitly. payload_sample
     * past payload_len may contain stale per-CPU data — userspace
     * truncates to payload_len so the tail is never observed. */
    evp->has_ts_option = 0;

    /* --- Core fields --- */
    evp->src_ip   = ip.saddr;
    evp->dst_ip   = ip.daddr;
    evp->src_port = tcp.source;
    evp->dst_port = tcp.dest;
    evp->pkt_len  = skb->len;

    /* --- Deep inspection fields --- */
    evp->ttl             = ip.ttl;
    evp->window_size     = tcp.window;
    evp->ip_tos          = ip.tos;
    evp->tcp_data_offset = tcp.doff;
    evp->ip_id           = ip.id;
    evp->ip_frag_off     = ip.frag_off;
    evp->tcp_seq         = bpf_ntohl(tcp.seq);

    /* --- Flag bitmap --- */
    evp->tcp_flags =
        (tcp.syn ? 1  : 0) |
        (tcp.ack ? 2  : 0) |
        (tcp.fin ? 4  : 0) |
        (tcp.rst ? 8  : 0) |
        (tcp.psh ? 16 : 0) |
        (tcp.urg ? 32 : 0);

    /* --- Per-port capture depth lookup (Idea 30 Phase 0) ---
     * tcp.dest is network-byte-order; userspace populates monitored_ports
     * with host-byte-order keys. Convert before lookup. */
    u16 dport_hbo = bpf_ntohs(tcp.dest);
    u32 *port_depth = monitored_ports.lookup(&dport_hbo);
    u32 capture_depth = DEPTH_BASE;
    if (port_depth) {
        u32 v = *port_depth;
        /* Clamp to one of the tier sizes — the only values the constant-
         * bounded load blocks below know how to handle. */
        if (v >= DEPTH_FULL)      capture_depth = DEPTH_FULL;
        else if (v >= DEPTH_MID)  capture_depth = DEPTH_MID;
        else                      capture_depth = DEPTH_BASE;
    }
    evp->capture_depth = capture_depth;

    /* --- Payload sample (tiered constant-bounded loads) ---
     * Verifier requires constant-sized bpf_skb_load_bytes calls. We do up
     * to three loads, each gated by `capture_depth >= TIER && avail >= TIER`.
     * For un-monitored ports only the first 256-byte load executes —
     * preserving exact pre-Phase-0 behaviour. */
    u32 tcp_hdr_len  = tcp.doff * 4;
    u32 payload_off  = sizeof(struct ethhdr) + sizeof(struct iphdr) + tcp_hdr_len;
    u32 total_len    = skb->len;
    u32 avail        = (total_len > payload_off) ? (total_len - payload_off) : 0;

    u16 captured = 0;
    if (avail >= DEPTH_BASE) {
        bpf_skb_load_bytes(skb, payload_off, evp->payload_sample, DEPTH_BASE);
        captured = DEPTH_BASE;
    } else if (avail > 0 && avail < DEPTH_BASE) {
        /* Short packet — copy DEPTH_BASE bytes anyway (zeros past `avail`
         * already, thanks to memset). Verifier-friendly: constant length. */
        bpf_skb_load_bytes(skb, payload_off, evp->payload_sample, DEPTH_BASE);
        captured = (u16)avail;
    }

    if (capture_depth >= DEPTH_MID && avail >= DEPTH_MID) {
        /* Load the next 768 bytes (offset 256, length 768 — both constant). */
        bpf_skb_load_bytes(skb, payload_off + DEPTH_BASE,
                           evp->payload_sample + DEPTH_BASE,
                           DEPTH_MID - DEPTH_BASE);
        captured = DEPTH_MID;
    }

    if (capture_depth >= DEPTH_FULL && avail >= DEPTH_FULL) {
        /* Load the next 3072 bytes (offset 1024, length 3072 — constant).
         * Phase 0.5 (2026-05-22): added after the 2026-05-21 incident
         * where a 2120-byte exploit POST body sat past the 1 KB ceiling
         * and Phase 0 capture missed it. With the whole-struct memset
         * removed earlier this tier no longer trips the verifier. */
        bpf_skb_load_bytes(skb, payload_off + DEPTH_MID,
                           evp->payload_sample + DEPTH_MID,
                           DEPTH_FULL - DEPTH_MID);
        captured = DEPTH_FULL;
    }

    /* If the actual on-wire payload is less than the captured tier, cap
     * payload_len at avail so userspace knows where valid bytes end. */
    if (avail < captured) captured = (u16)avail;
    evp->payload_len = captured;

    /* --- TCP timestamp option probe (kind=8 at offset TCP+20) --- */
    if (tcp.doff > 5) {
        /* Simplified: check for NOP+NOP+TS at standard offset */
        u32 opt_off = sizeof(struct ethhdr) + sizeof(struct iphdr) + 20;
        if (opt_off + 2 < total_len) {
            u8 byte0 = 0, byte1 = 0, byte2 = 0;
            bpf_skb_load_bytes(skb, opt_off,     &byte0, 1);
            bpf_skb_load_bytes(skb, opt_off + 1, &byte1, 1);
            bpf_skb_load_bytes(skb, opt_off + 2, &byte2, 1);
            /* NOP=1, NOP=1, TS_KIND=8 */
            if (byte0 == 1 && byte1 == 1 && byte2 == 8)
                evp->has_ts_option = 1;
        }
    }

    /* ====== CLASSIFICATION ENGINE ====== */

    /* SYN Scan — SYN only, no ACK, no FIN */
    if (tcp.syn && !tcp.ack && !tcp.fin)
        evp->scan_type = SCAN_SYN;

    /* FIN Scan — FIN only */
    else if (tcp.fin && !tcp.syn && !tcp.ack && !tcp.psh && !tcp.urg)
        evp->scan_type = SCAN_FIN;

    /* Maimon Scan — FIN+ACK */
    else if (tcp.fin && tcp.ack && !tcp.syn && !tcp.psh && !tcp.urg)
        evp->scan_type = SCAN_MAIMON;

    /* NULL Scan — no flags at all */
    else if (!tcp.syn && !tcp.fin && !tcp.ack && !tcp.rst && !tcp.psh && !tcp.urg)
        evp->scan_type = SCAN_NULL;

    /* XMAS Scan — FIN+PSH+URG */
    else if (tcp.fin && tcp.psh && tcp.urg)
        evp->scan_type = SCAN_XMAS;

    /* Window Scan — ACK only with zero window */
    else if (tcp.ack && !tcp.syn && !tcp.fin && tcp.window == 0 && skb->len <= 80)
        evp->scan_type = SCAN_WINDOW;

    /* ACK Scan — ACK only, small packet */
    else if (tcp.ack && !tcp.syn && !tcp.fin && skb->len <= 80)
        evp->scan_type = SCAN_ACK;

    /* Normal traffic */
    else
        evp->scan_type = SCAN_NORMAL;

    events.perf_submit(skb, evp, sizeof(*evp));
    return -1;
}
