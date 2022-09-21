/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef HELPERS_H
#define HELPERS_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_F_CURRENT_NETNS -1L

#ifndef ENABLE_IPV4
#define ENABLE_IPV4 1
#endif

#ifndef ENABLE_IPV6
#define ENABLE_IPV6 0
#endif

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifdef PRINTNL
#define PRINT_SUFFIX "\n"
#else
#define PRINT_SUFFIX ""
#endif

#ifndef printk
#define printk(fmt, ...)                                                       \
    ({                                                                         \
        char ____fmt[] = fmt PRINT_SUFFIX;                                     \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })
#endif

#define debugf(fmt, ...)                                                       \
    ({                                                                         \
        char ____fmt[] = "[debug] " fmt PRINT_SUFFIX;                          \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })

#ifndef memset
#define memset(dst, src, len) __builtin_memset(dst, src, len)
#endif

static const __u32 ip_zero = 0;
// 127.0.0.1 (network order)
static const __u32 localhost = 127 + (1 << 24);

static inline __u32 get_ipv4(__u32 *ip) { return ip[3]; }

static inline void set_ipv4(__u32 *dst, __u32 src)
{
    memset(dst, 0, sizeof(__u32) * 3);
    dst[3] = src;
}

static inline int is_port_listen_current_ns(void *ctx, __u32 ip, __u16 port)
{

    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.dport = bpf_htons(port);
    tuple.ipv4.daddr = ip;
    struct bpf_sock *s = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}

static inline int is_port_listen_udp_current_ns(void *ctx, __u32 ip, __u16 port)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.dport = bpf_htons(port);
    tuple.ipv4.daddr = ip;
    struct bpf_sock *s = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}

static const __u32 ip_zero6[4] = {0, 0, 0, 0};
// ::1 (network order)
static const __u32 localhost6[4] = {0, 0, 0, 1 << 24};

static inline void set_ipv6(__u32 *dst, __u32 *src)
{
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

static inline int ipv6_equal(__u32 *a, __u32 *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static inline int is_port_listen_current_ns6(void *ctx, __u32 *ip, __u16 port)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv6.dport = bpf_htons(port);
    set_ipv6(tuple.ipv6.daddr, ip);
    struct bpf_sock *s = bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv6),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}

static inline int is_port_listen_udp_current_ns6(void *ctx, __u32 *ip,
                                                 __u16 port)
{
    struct bpf_sock_tuple tuple = {};
    tuple.ipv6.dport = bpf_htons(port);
    set_ipv6(tuple.ipv6.daddr, ip);
    struct bpf_sock *s = bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv6),
                                           BPF_F_CURRENT_NETNS, 0);
    if (s) {
        bpf_sk_release(s);
        return 1;
    }
    return 0;
}

struct origin_info {
    __u32 ip[4];
    __u32 pid;
    __u16 port;
    // last bit means that ip of process is detected.
    __u16 flags;
};

struct pair {
    __u32 sip[4];
    __u32 dip[4];
    __u16 sport;
    __u16 dport;
};

#define MAX_ITEM_LEN 10

struct cidr {
    __u32 net; // network order
    __u8 mask;
    __u8 __pad[3];
};

static inline int is_in_cidr(struct cidr *c, __u32 ip)
{
    return (bpf_htonl(c->net) >> (32 - c->mask)) ==
           bpf_htonl(ip) >> (32 - c->mask);
}

struct pod_config {
    __u16 status_port;
    __u16 __pad;
    struct cidr exclude_out_ranges[MAX_ITEM_LEN];
    struct cidr include_out_ranges[MAX_ITEM_LEN];
    __u16 include_in_ports[MAX_ITEM_LEN];
    __u16 include_out_ports[MAX_ITEM_LEN];
    __u16 exclude_in_ports[MAX_ITEM_LEN];
    __u16 exclude_out_ports[MAX_ITEM_LEN];
};

#define IS_EXCLUDE_PORT(ITEM, PORT, RET)                                       \
    do {                                                                       \
        *RET = 0;                                                              \
        for (int i = 0; i < MAX_ITEM_LEN && ITEM[i] != 0; i++) {               \
            if (bpf_htons(PORT) == ITEM[i]) {                                  \
                *RET = 1;                                                      \
                break;                                                         \
            }                                                                  \
        }                                                                      \
    } while (0);

#define IS_EXCLUDE_IPRANGES(ITEM, IP, RET)                                     \
    do {                                                                       \
        *RET = 0;                                                              \
        for (int i = 0; i < MAX_ITEM_LEN && ITEM[i].net != 0; i++) {           \
            if (is_in_cidr(&ITEM[i], IP)) {                                    \
                *RET = 1;                                                      \
                break;                                                         \
            }                                                                  \
        }                                                                      \
    } while (0);

#define IS_INCLUDE_PORT(ITEM, PORT, RET)                                       \
    do {                                                                       \
        *RET = 0;                                                              \
        if (ITEM[0] != 0) {                                                    \
            for (int i = 0; i < MAX_ITEM_LEN && ITEM[i] != 0; i++) {           \
                if (bpf_htons(PORT) == ITEM[i]) {                              \
                    *RET = 1;                                                  \
                    break;                                                     \
                }                                                              \
            }                                                                  \
        } else {                                                               \
            *RET = 1;                                                          \
        }                                                                      \
    } while (0);

#define IS_INCLUDE_IPRANGES(ITEM, IP, RET)                                     \
    do {                                                                       \
        *RET = 0;                                                              \
        if (ITEM[0].net != 0) {                                                \
            for (int i = 0; i < MAX_ITEM_LEN && ITEM[i].net != 0; i++) {       \
                if (is_in_cidr(&ITEM[i], IP)) {                                \
                    *RET = 1;                                                  \
                    break;                                                     \
                }                                                              \
            }                                                                  \
        } else {                                                               \
            *RET = 1;                                                          \
        }                                                                      \
    } while (0);

#endif
