/*
 * LIDRA v3 eBPF Probe
 * Kernel-level security monitoring
 * 
 * Hooks: execve, connect, openat, vfs_write
 * Output: Perf ring buffer to userspace
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <net/sock.h>
#include <asm/uaccess.h>

#define MAX_STRING_SIZE 256
#define MAX_PATH_SIZE 512
#define MAX_CONNECTIONS 10000

struct event_data {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u32 event_type;  // 1=exec, 2=connect, 3=open, 4=write
    __u32 ret;
    char filename[MAX_PATH_SIZE];
    char args[MAX_STRING_SIZE];
    __u32 src_port;
    __u32 dst_port;
    __u8 protocol;  // TCP=6, UDP=17
    __u8 ip_version;  // 4=IPv4, 6=IPv6
    __u8 src_ip[16];
    __u8 dst_ip[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, struct event_data);
    __uint(max_entries, 128);
} events SEC(".maps");

static __always_inline int get_sock_addr(void *addr, __u8 *ip, __u16 *port, __u8 version) {
    if (version == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        __builtin_memcpy(ip, &sin->sin_addr, 4);
        *port = bpf_ntohs(sin->sin_port);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        __builtin_memcpy(ip, &sin6->sin6_addr, 16);
        *port = bpf_ntohs(sin6->sin6_port);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_data event = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = 1;  // exec
    
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    
    // Get filename (first argument)
    if (ctx->args[0]) {
        bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[0]);
    }
    
    // Get arguments (up to 200 chars total)
    if (ctx->args[1]) {
        bpf_probe_read_user(event.args, sizeof(event.args), (void *)ctx->args[1]);
    }
    
    // Detect suspicious commands
    if (event.filename[0] == '/') {
        // Check for suspicious paths
        if (bpf_strncmp(event.filename, 9, "/bin/bash") == 0 ||
            bpf_strncmp(event.filename, 8, "/bin/sh") == 0) {
            // Shell execution detected - potential concern
        }
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_data event = {0};
    struct sock *sock = (struct sock *)ctx->args[0];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = 2;  // connect
    
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    
    // Get socket family
    if (addr) {
        __u16 family = 0;
        bpf_probe_read(&family, sizeof(family), (void *)&addr->sa_family);
        
        if (family == AF_INET) {
            event.ip_version = 4;
            get_sock_addr(addr, event.dst_ip, &event.dst_port, 4);
        } else if (family == AF_INET6) {
            event.ip_version = 6;
            get_sock_addr(addr, event.dst_ip, &event.dst_port, 6);
        }
        
        // Get source port from socket
        if (sock) {
            __u16 sport = 0;
            bpf_probe_read(&sport, sizeof(sport), (void *)&sock->sk_num);
            event.src_port = sport;
            
            // Get protocol
            __u8 proto = 0;
            bpf_probe_read(&proto, sizeof(proto), (void *)&sock->sk_protocol);
            event.protocol = proto;
        }
    }
    
    // Flag suspicious ports (common C2 ports)
    // 4444 = Metasploit, 5555 = ADB, 31337 = Back Orifice
    if (event.dst_port == 4444 || event.dst_port == 5555 || 
        event.dst_port == 31337 || event.dst_port == 1337) {
        // Mark as suspicious connection
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_data event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = 3;  // open
    
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    
    // Get filename
    if (ctx->args[0]) {
        bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[0]);
    }
    
    // Detect sensitive file access
    // /etc/passwd, /etc/shadow, .ssh, etc.
    if (event.filename[0] == '/') {
        // Check for sensitive paths
        __u32 sensitive_paths[] = {
            0x2F657463,  // /etc
            0x2F766172,  // /var
            0x2F70726F,  // /proc
            0x2F726F6F,  // /root
            0x2F2E7373,  // /.ssh
        };
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    struct event_data event = {0};
    __u64 fd = ctx->args[0];
    
    // Only track file writes, not stdout/stderr (1, 2)
    if (fd <= 2) {
        return 0;
    }
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = 4;  // write
    
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    
    // Could add file descriptor to path mapping in future
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_enter_kill(struct trace_event_raw_sys_enter *ctx) {
    struct event_data event = {0};
    __s32 pid = ctx->args[0];
    __s32 sig = ctx->args[1];
    
    // Only track SIGKILL (9) - process termination
    if (sig != 9) {
        return 0;
    }
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.event_type = 5;  // kill
    
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    event.ret = pid;  // Store target PID in ret field
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("socket/kfree_skb")
int trace_sock_queue(struct sk_buff *skb) {
    struct event_data event = {0};
    
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = 6;  // network packet
    
    // Could extract IP/port info from skb here for network analysis
    
    // Limited visibility here - would need socket filters for full packet capture
    
    return 0;
}

char _license[] SEC("license") = "GPL";