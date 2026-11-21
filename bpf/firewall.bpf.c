// SPDX-License-Identifier: (MIT OR GPL-2.0)
//
// Per-sandbox egress firewall.
//
// Every sandbox gets its own cgroup v2 and its own copy of these programs and
// maps, so policies never leak between sandboxes. Enforcement happens at two
// layers:
//
//   1. Socket layer (cgroup/connect4, cgroup/sendmsg4, and the v6 variants):
//      denied connects fail fast with EPERM, which gives the workload a clear
//      error instead of a hanging SYN.
//   2. Packet layer (cgroup_skb/egress): a default-deny backstop for anything
//      that bypasses the socket hooks (raw sockets, ICMP, unconnected paths).
//
// Allowed destinations live in an LPM trie keyed by {port, IPv4 prefix}. Port
// 0 means "any port". A lookup tries the exact port first, then port 0.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define VERDICT_DENY 0
#define VERDICT_ALLOW 1

#define STAT_CONN_DENIED 0
#define STAT_CONN_ALLOWED 1
#define STAT_PKT_DROPPED 2
#define STAT_MAX 3

enum hook {
	HOOK_CONNECT4 = 1,
	HOOK_SENDMSG4 = 2,
	HOOK_CONNECT6 = 3,
	HOOK_SENDMSG6 = 4,
	HOOK_EGRESS = 5,
};

// LPM trie key. prefixlen counts bits of the data that follows it:
// 16 (port) + 16 (pad, always zero) + CIDR bits of addr.
struct lpm_key {
	__u32 prefixlen;
	__u16 port; // network byte order, 0 = any port
	__u16 pad;
	__u32 addr; // network byte order
};

struct event {
	__u64 ts_ns;
	__u32 daddr; // network byte order (0 for IPv6)
	__u16 dport; // network byte order
	__u8 hook;
	__u8 verdict;
	__u8 proto;
	__u8 pad[7];
};

struct settings {
	__u32 allow_icmp;
	__u32 log_allowed;
	__u32 allow_loopback;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 1024);
} allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct settings);
	__uint(max_entries, 1);
} settings_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Only used through a ring buffer pointer; this keeps it in BTF for bpf2go.
const struct event *unused_event __attribute__((unused));

static __always_inline struct settings *get_settings(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&settings_map, &key);
}

static __always_inline void count(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&stats, &idx);
	if (c)
		(*c)++; // per-CPU slot, no atomics needed
}

static __always_inline int allowed_v4(__u32 daddr, __u16 dport)
{
	struct lpm_key k = {
		.prefixlen = 64,
		.port = dport,
		.pad = 0,
		.addr = daddr,
	};

	if (bpf_map_lookup_elem(&allow_v4, &k))
		return 1;
	k.port = 0;
	return bpf_map_lookup_elem(&allow_v4, &k) != NULL;
}

static __always_inline void emit(__u8 hook, __u8 verdict, __u8 proto, __u32 daddr, __u16 dport)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return; // ring full: stats still count the decision

	e->ts_ns = bpf_ktime_get_ns();
	e->daddr = daddr;
	e->dport = dport;
	e->hook = hook;
	e->verdict = verdict;
	e->proto = proto;
	__builtin_memset(e->pad, 0, sizeof(e->pad));
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int decide_v4(struct bpf_sock_addr *ctx, __u8 hook)
{
	__u32 daddr = ctx->user_ip4;
	__u16 dport = (__u16)ctx->user_port;
	__u8 proto = (__u8)ctx->protocol;
	struct settings *s = get_settings();
	int ok = allowed_v4(daddr, dport);

	count(ok ? STAT_CONN_ALLOWED : STAT_CONN_DENIED);
	if (!ok || (s && s->log_allowed))
		emit(hook, ok ? VERDICT_ALLOW : VERDICT_DENY, proto, daddr, dport);
	return ok;
}

static __always_inline int is_v6_loopback(struct bpf_sock_addr *ctx)
{
	return ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && ctx->user_ip6[2] == 0 &&
	       ctx->user_ip6[3] == bpf_htonl(1);
}

static __always_inline int decide_v6(struct bpf_sock_addr *ctx, __u8 hook)
{
	struct settings *s = get_settings();
	int ok = s && s->allow_loopback && is_v6_loopback(ctx);

	count(ok ? STAT_CONN_ALLOWED : STAT_CONN_DENIED);
	if (!ok)
		emit(hook, VERDICT_DENY, (__u8)ctx->protocol, 0, (__u16)ctx->user_port);
	return ok;
}

SEC("cgroup/connect4")
int sbx_connect4(struct bpf_sock_addr *ctx)
{
	return decide_v4(ctx, HOOK_CONNECT4);
}

SEC("cgroup/sendmsg4")
int sbx_sendmsg4(struct bpf_sock_addr *ctx)
{
	return decide_v4(ctx, HOOK_SENDMSG4);
}

// IPv6 egress is denied except loopback; the policy language is IPv4-only.
SEC("cgroup/connect6")
int sbx_connect6(struct bpf_sock_addr *ctx)
{
	return decide_v6(ctx, HOOK_CONNECT6);
}

SEC("cgroup/sendmsg6")
int sbx_sendmsg6(struct bpf_sock_addr *ctx)
{
	return decide_v6(ctx, HOOK_SENDMSG6);
}

SEC("cgroup_skb/egress")
int sbx_egress(struct __sk_buff *skb)
{
	struct settings *s = get_settings();
	struct iphdr iph;
	__u16 dport = 0;
	int ok = 0;

	if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		__u32 dst[4];

		if (bpf_skb_load_bytes(skb, 24, dst, sizeof(dst)) < 0)
			goto drop;
		ok = s && s->allow_loopback && dst[0] == 0 && dst[1] == 0 && dst[2] == 0 &&
		     dst[3] == bpf_htonl(1);
		if (!ok)
			goto drop;
		return 1;
	}
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return 1;

	if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0)
		goto drop;

	if (iph.frag_off & bpf_htons(0x1FFF)) {
		// Non-first fragment: no L4 header. Only pass if the host is
		// allowed on every port.
		ok = allowed_v4(iph.daddr, 0);
	} else if (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) {
		__u32 off = (__u32)iph.ihl * 4;
		__u16 ports[2];

		if (off < sizeof(iph) || off > 60)
			goto drop;
		if (bpf_skb_load_bytes(skb, off, ports, sizeof(ports)) < 0)
			goto drop;
		dport = ports[1];
		ok = allowed_v4(iph.daddr, dport);
	} else if (iph.protocol == IPPROTO_ICMP) {
		ok = s && s->allow_icmp && allowed_v4(iph.daddr, 0);
	}

	if (ok)
		return 1;

	count(STAT_PKT_DROPPED);
	emit(HOOK_EGRESS, VERDICT_DENY, iph.protocol, iph.daddr, dport);
	return 0;

drop:
	count(STAT_PKT_DROPPED);
	return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
