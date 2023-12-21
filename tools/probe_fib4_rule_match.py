#!/usr/bin/env python
from bcc import BPF


bpf_source = """
#include <uapi/linux/ptrace.h>
#include <net/fib_rules.h>
#include <bcc/proto.h>

struct fib4_rule {
	struct fib_rule		common;
	u8			dst_len;
	u8			src_len;
	u8			dscp;
	u32			src;
	u32			srcmask;
	u32			dst;
	u32			dstmask;
	u32			tclassid;
};


int do_fib4_rule_match(struct pt_regs *ctx, struct fib4_rule *rule, struct flowi *fl, int flags) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    struct flowi4 *fl4 = &fl->u.ip4;

    u64 id =  bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    bpf_trace_printk("%s-%d ---------------- ", comm, pid);
    bpf_trace_printk("  flow: %x -> %x ", fl4->saddr, fl4->daddr);
    bpf_trace_printk("  rule: %x -> %x [%d]", rule->src, rule->dst, rule->common.table);
    return 0;
}
"""

bpf = BPF(text = bpf_source)	 
probe_function = "fib4_rule_match" # bpf.get_syscall_fnname("fib4_rule_match")		 
bpf.attach_kprobe(event = probe_function, fn_name = "do_fib4_rule_match")	 
bpf.trace_print()

