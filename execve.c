//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// This is the structure that will be passed from the Linux Kernel to our Go program
struct event {
    __u32 pid;
    __u8 comm[16];
};

// This defines a Ring Buffer, which is a highly performant way for eBPF to send data to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// We attach to the 'execve' system call (triggered whenever a new process starts)
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx) {
    // Get the Process ID
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    struct event *e;

    // Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Populate the struct with the PID and the Command Name (comm)
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Send it to user-space!
    bpf_ringbuf_submit(e, 0);

    return 0;
}
