// SPDX-License-Identifier: GPL-2.0-only OR MIT
//
// Attributes new connections to the processes that open them.
//
// Each hook runs in the context of the process that is connecting or sending, at a point where the flow's addresses
// and ports are known and before its first packet leaves: tcp_connect() runs after the source port is chosen and
// before the SYN is built, and inet_sendmsg() binds a source port before it calls udp_sendmsg(). So by the time
// NFQUEUE hands the first packet to the daemon, its owner is already in the `flows` map, keyed exactly by the flow.
//
// Kernel structures are declared with only the fields read, and `preserve_access_index`: libbpf-style CO-RE
// relocations fit them to the running kernel's layout (from its BTF), so one object runs on every kernel.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

typedef struct {
	struct net *net;
} possible_net_t;

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct in_addr {
	__be32 s_addr;
} __attribute__((preserve_access_index));

struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
} __attribute__((preserve_access_index));

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
} __attribute__((preserve_access_index));

struct msghdr {
	void *msg_name;
	int msg_namelen;
} __attribute__((preserve_access_index));

// A flow, as the first packet's headers and its socket's network namespace identify it. Ports in host byte order;
// an IPv4 address in the first four bytes of `daddr`, the rest zero. 28 bytes, no padding.
struct flow_key {
	__u32 netns;
	__u8 protocol;
	__u8 family;
	__u16 sport;
	__u16 dport;
	__u16 zero;
	__u8 daddr[16];
};

// Who opened it. 48 bytes, no padding.
struct flow_owner {
	__u64 cgroup;
	__u64 ktime;
	__u32 tgid;
	__u32 tid;
	__u32 uid;
	__u32 gid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_owner);
} flows SEC(".maps");

// An IPv6 socket talking to an IPv4 address (::ffff:a.b.c.d) sends IPv4 packets: key it as IPv4.
static __always_inline void unmap_v4(struct flow_key *key)
{
	if (key->family != AF_INET6)
		return;
	for (int i = 0; i < 10; i++)
		if (key->daddr[i])
			return;
	if (key->daddr[10] != 0xff || key->daddr[11] != 0xff)
		return;
	key->family = AF_INET;
	__builtin_memcpy(key->daddr, &key->daddr[12], 4);
	__builtin_memset(&key->daddr[4], 0, 12);
}

static __always_inline void record(struct flow_key *key)
{
	struct flow_owner owner = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	owner.cgroup = bpf_get_current_cgroup_id();
	owner.ktime = bpf_ktime_get_ns();
	owner.tgid = pid_tgid >> 32;
	owner.tid = (__u32)pid_tgid;
	owner.uid = (__u32)uid_gid;
	owner.gid = uid_gid >> 32;
	bpf_get_current_comm(owner.comm, sizeof(owner.comm));
	unmap_v4(key);
	bpf_map_update_elem(&flows, key, &owner, BPF_ANY);
}

static __always_inline int key_from_sock(struct flow_key *key, struct sock *sk, __u8 protocol)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	key->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
	key->protocol = protocol;
	key->family = family;
	key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	key->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (family == AF_INET) {
		__be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		__builtin_memcpy(key->daddr, &daddr, 4);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&key->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		return 0;
	}
	return 1;
}

SEC("fentry/tcp_connect")
int BPF_PROG(on_tcp_connect, struct sock *sk)
{
	struct flow_key key = {};

	if (key_from_sock(&key, sk, IPPROTO_TCP))
		record(&key);
	return 0;
}

// A UDP datagram: to the address given with it (sendto), or the socket's (connected sockets).
static __always_inline int on_udp(struct sock *sk, struct msghdr *msg)
{
	struct flow_key key = {};
	void *name = BPF_CORE_READ(msg, msg_name);

	if (!key_from_sock(&key, sk, IPPROTO_UDP))
		return 0;
	if (name) {
		unsigned short family = 0;

		bpf_probe_read_kernel(&family, sizeof(family), name);
		if (family == AF_INET) {
			struct sockaddr_in *sin = name;
			__be32 daddr = BPF_CORE_READ(sin, sin_addr.s_addr);

			key.family = AF_INET;
			key.dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
			__builtin_memset(key.daddr, 0, sizeof(key.daddr));
			__builtin_memcpy(key.daddr, &daddr, 4);
		} else if (family == AF_INET6) {
			struct sockaddr_in6 *sin6 = name;

			key.family = AF_INET6;
			key.dport = bpf_ntohs(BPF_CORE_READ(sin6, sin6_port));
			BPF_CORE_READ_INTO(&key.daddr, sin6, sin6_addr.in6_u.u6_addr8);
		}
	}
	record(&key);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return on_udp(sk, msg);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
	return on_udp(sk, msg);
}
