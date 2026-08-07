#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline int parse_eth_proto(void **data, void *data_end, __u16 *eth_proto)
{
    struct ethhdr *eth = *data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u16 proto = eth->h_proto;
    *data = eth + 1;

    /* Basic single VLAN (802.1Q/AD) handling. */
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct {
            __be16 tci;
            __be16 encap_proto;
        } *vh = *data;
        if ((void *)(vh + 1) > data_end)
            return -1;
        proto = vh->encap_proto;
        *data = vh + 1;
    }

    *eth_proto = bpf_ntohs(proto);
    return 0;
}

static __always_inline int ipv6_l4_is_userspace(__u8 protocol, __u8 *cursor,
                                                void *data_end)
{
    if (protocol == IPPROTO_UDP || protocol == IPPROTO_TCP)
        return 1;
    if (protocol != IPPROTO_ICMPV6 || cursor + 1 > (__u8 *)data_end)
        return 0;

    /* Only ICMPv6 errors belong to the userspace socket error path.
     * Echo and Neighbor Discovery must remain available to the kernel. */
    return cursor[0] >= 1 && cursor[0] <= 4;
}

/* Return true when an IPv6 packet's extension-header chain identifies a
 * transport packet or an ICMPv6 error handled by the userspace stack. */
static __always_inline int ipv6_is_userspace_transport(void *data, void *data_end)
{
    struct ipv6hdr *ip6 = data;
    if ((void *)(ip6 + 1) > data_end)
        return 0;

    __u8 nh = ip6->nexthdr;
    __u8 *cursor = (__u8 *)(ip6 + 1);

    /* Keep this parser deliberately small: old kernels reject the large
     * verifier state space produced by an unrolled extension-header loop.
     * The common one-extension and Fragment-header forms are covered; other
     * chains safely fall back to the kernel. */
    if (ipv6_l4_is_userspace(nh, cursor, data_end))
        return 1;

    if (nh == IPPROTO_FRAGMENT) {
        struct {
            __u8 nexthdr;
            __u8 reserved;
            __u16 frag_off;
            __u32 identification;
        } *fh = (void *)cursor;
        if ((void *)(fh + 1) > data_end)
            return 0;
        return fh->nexthdr == IPPROTO_UDP || fh->nexthdr == IPPROTO_TCP;
    }

    if (nh != IPPROTO_HOPOPTS && nh != IPPROTO_ROUTING &&
        nh != IPPROTO_DSTOPTS)
        return 0;
    if (cursor + 2 > (__u8 *)data_end)
        return 0;

    __u8 next = cursor[0];
    __u32 hdr_len = ((__u32)cursor[1] + 1u) * 8u;
    if (hdr_len < 8u || cursor + hdr_len > (__u8 *)data_end)
        return 0;
    cursor += hdr_len;
    if (ipv6_l4_is_userspace(next, cursor, data_end))
        return 1;
    if (next != IPPROTO_FRAGMENT)
        return 0;

    struct {
        __u8 nexthdr;
        __u8 reserved;
        __u16 frag_off;
        __u32 identification;
    } *fh = (void *)cursor;
    if ((void *)(fh + 1) > data_end)
        return 0;
    return fh->nexthdr == IPPROTO_UDP || fh->nexthdr == IPPROTO_TCP;
}

/* This program is used with AF_XDP multi-buffer receive enabled.  The
 * frags variant tells the kernel that the XDP program is safe to run on
 * frames carrying XDP_PKT_CONTD fragments. */
SEC("xdp.frags")
int xdp_redirect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 eth_proto = 0;
    if (parse_eth_proto(&data, data_end, &eth_proto) != 0)
        return XDP_PASS;

	/* IPv6 TCP/UDP and ICMPv6 errors are handled by userspace.  ICMPv6
	 * informational traffic, including NDP and echo, remains in the kernel. */
	if (eth_proto == ETH_P_IPV6) {
		if (!ipv6_is_userspace_transport(data, data_end))
			return XDP_PASS;
		__u32 qid = ctx->rx_queue_index;
		if (!bpf_map_lookup_elem(&xsks_map, &qid))
			return XDP_PASS;
		return bpf_redirect_map(&xsks_map, qid, 0);
	}
	if (eth_proto != ETH_P_IP)
		return XDP_PASS;
	struct iphdr *ip = data;
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->ihl < 5 || (void *)ip + ((__u32)ip->ihl * 4u) > data_end)
		return XDP_PASS;

	/* IPv4 multicast is handled by the normal kernel path.  Do not
	 * redirect it to AF_XDP; otherwise multicast destination MACs (01:00:5e)
	 * reach userspace and are rejected later by ether_recv(). */
	if ((bpf_ntohl(ip->daddr) & 0xf0000000U) == 0xe0000000U)
		return XDP_PASS;

    /* UDP/TCP/ICMP are handled by the current userspace stack. */
    if (ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP ||
        ip->protocol == IPPROTO_ICMP) {
        __u32 qid = ctx->rx_queue_index;
        if (!bpf_map_lookup_elem(&xsks_map, &qid))
            return XDP_PASS;
        return bpf_redirect_map(&xsks_map, qid, 0);
    }


    /* other protocols: pass */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
