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

#include "headers/helpers.h"
#include "headers/maps.h"

#define MAX_OPS_BUFF_LENGTH 4096
#define SO_ORIGINAL_DST 80

__section("cgroup/getsockopt") int mb_get_sockopt(struct bpf_sockopt *ctx)
{
    // currently, eBPF can not deal with optlen more than 4096 bytes, so, we
    // should limit this.
    if (ctx->optlen > MAX_OPS_BUFF_LENGTH) {
        ctx->optlen = MAX_OPS_BUFF_LENGTH;
    }

    // envoy will call getsockopt with SO_ORIGINAL_DST, we should rewrite it to
    // return original dst info.
    if (ctx->optname != SO_ORIGINAL_DST) {
        return 1;
    }

    struct bpf_sock *sk = ctx->sk;

    if (!sk) {
        return 1;
    }

    struct pair p;
    memset(&p, 0, sizeof(p));
    p.dport = bpf_htons(sk->src_port);
    p.sport = sk->dst_port;
    struct origin_info *origin;
    switch (sk->family) {
#if ENABLE_IPV4
    case 2: // ipv4
        set_ipv4(p.dip, sk->src_ip4);
        set_ipv4(p.sip, sk->dst_ip4);
        origin = bpf_map_lookup_elem(&pair_orig_dst, &p);
        if (origin) {
            // rewrite original_dst
            void *optval = (void *)ctx->optval;
            void *optval_end = (void *)ctx->optval_end;
            struct sockaddr_in *sockaddr = optval;

            if (optval + sizeof(struct sockaddr_in) > optval_end) {
                printk("getso : invalid getsockopt optval: optname: %d",
                       ctx->optname);
                return 1;
            }

            ctx->retval = 0;

            struct sockaddr_in sa = {
                .sin_family = ctx->sk->family,
                .sin_addr.s_addr = get_ipv4(origin->ip),
                .sin_port = origin->port,
            };

            *sockaddr = sa;
        }

        break;
#endif
#if ENABLE_IPV6
    case 10: // ipv6
        // TODO (bartsmykla): refactor as when using set_ipv6:
        //  from 24 to 72:
        //   R1=inv10
        //   R2=inv4097
        //   R6=ctx(id=0,off=0,imm=0)
        //   R10=fp0
        //   fp-8=????mmmm fp-16=00000000 fp-24=00000000 fp-32=00000000
        //   fp-40=00000000
        //  ;
        //  72: (b7) r1 = 28
        //  ; set_ipv6(p.dip, ctx->sk->src_ip6);
        //  73: (79) r2 = *(u64 *)(r6 +0)
        //  74: (bf) r3 = r2
        //  75: (0f) r3 += r1
        //  last_idx 75 first_idx 24
        //  regs=2 stack=0 before 74: (bf) r3 = r2
        //  regs=2 stack=0 before 73: (79) r2 = *(u64 *)(r6 +0)
        //  regs=2 stack=0 before 72: (b7) r1 = 28
        //  R3 pointer arithmetic on sock prohibited

        p.dip[0] = ctx->sk->src_ip6[0];
        p.dip[1] = ctx->sk->src_ip6[1];
        p.dip[2] = ctx->sk->src_ip6[2];
        p.dip[3] = ctx->sk->src_ip6[3];
        p.sip[0] = ctx->sk->dst_ip6[0];
        p.sip[1] = ctx->sk->dst_ip6[1];
        p.sip[2] = ctx->sk->dst_ip6[2];
        p.sip[3] = ctx->sk->dst_ip6[3];

        origin = bpf_map_lookup_elem(&pair_orig_dst, &p);
        if (origin) {
            // rewrite original_dst
            void *optval = (void *)ctx->optval;
            void *optval_end = (void *)ctx->optval_end;
            struct sockaddr_in6 *sockaddr = optval;

            if (optval + sizeof(*sockaddr) > optval_end) {
                printk("getso : invalid getsockopt optval: optname: %d",
                       ctx->optname);
                return 1;
            }

            ctx->retval = 0;
            ctx->optlen = (__s32)sizeof(*sockaddr);

            sockaddr->sin6_family = ctx->sk->family;
            sockaddr->sin6_port = origin->port;
            set_ipv6(sockaddr->sin6_addr.in6_u.u6_addr32, origin->ip);
        }
        break;
#endif
    }

    return 1;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
