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

#ifndef MAPS_H
#define MAPS_H

#include "helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cookie_orig_dst SEC(".maps");

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

// process_ip stores envoy's ip address.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} process_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(struct pair));
    __uint(value_size, sizeof(struct origin_info));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pair_orig_dst SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(struct pair));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_pair_map SEC(".maps");

#endif
