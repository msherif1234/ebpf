//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * This example copies parts of struct sock_common and struct sock from
 * the Linux kernel, but doesn't cause any CO-RE information to be emitted
 * into the ELF object. This requires the struct layout (up until the fields
 * that are being accessed) to match the kernel's, and the example will break
 * or misbehave when this is no longer the case.
 *
 * Also note that BTF-enabled programs like fentry, fexit, fmod_ret, tp_btf,
 * lsm, etc. declared using the BPF_PROG macro can read kernel memory without
 * needing to call bpf_probe_read*().
 */

/**
 * struct sock_common reflects the start of the kernel's struct sock_common.
 * It only contains the fields up until skc_family that are accessed in the
 * program, with padding to match the kernel's declaration.
 */
struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
	u8 comm[16];
};
struct event *unused __attribute__((unused));

SEC("kprobe/do_ipt_set_ctl")
int kprobe_do_ipt_set_ctl(struct sock *sk) {
	bpf_printk("Enter change iptables ruleset");
	return 0;
}

SEC("kprobe/do_ipt_get_ctl")
int kprobe_do_ipt_get_ctl(struct sock *sk) {
	bpf_printk("Enter change iptables rule get");
	return 0;
}

SEC("kprobe/ipt_do_table")
int kprobe_ipt_do_table(struct sock *sk) {
	struct event *ipt_info;
	bpf_printk("Enter IP tables packet processing");
	ipt_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!ipt_info) {
		bpf_printk("Null pointer");
		return 0;
	}

	bpf_get_current_comm(&ipt_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(ipt_info, 0);

	return 0;
}
