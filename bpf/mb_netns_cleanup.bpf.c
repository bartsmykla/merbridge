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
#include "headers/mesh.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u32) * 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} netns_pod_ips SEC(".maps");

// local_pods stores Pods' ips in current node.
// which can be set by controller.
// only contains injected pods.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32) * 4);
    __uint(value_size, sizeof(struct pod_config));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} local_pod_ips SEC(".maps");

SEC("fentry/net_ns_net_exit")
int BPF_PROG(net_ns_net_exit, struct net *net)
{
    __u64 netns_inum = BPF_CORE_READ(net, ns.inum);
    bpf_printk("KPROBE ENTRY  inum: %u\n", netns_inum);
    __u32 *ip = bpf_map_lookup_elem(&netns_pod_ips, &netns_inum);

    if (!ip) {
        debugf("clean : net namespace isn't in eBPF: %u", netns_inum);
    } else {
        __u32 curr_pod_ip = get_ipv4(ip);
        bpf_map_delete_elem(&local_pod_ips, ip);
        debugf("clean : removed ip for netns from local_pod_ips: "
               "netns_inum: %u, ip: %pI4",
               netns_inum, &curr_pod_ip);
        bpf_map_delete_elem(&netns_pod_ips, &netns_inum);
        debugf("clean : removed netns_inum for netns_pod_ips: "
               "netns_inum: %u",
               netns_inum);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
