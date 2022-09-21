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

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/pkt_cls.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "mb_tc.skel.h"

static struct env {
    bool verbose;
    char *bpffs;
    char *iface;
} env;

const char *argp_program_version = "mb_tc 0.1";
const char argp_program_doc[] =
    "BPF mb_tc loader.\n"
    "\n"
    "USAGE: ./mb_tc [-v|--verbose] [-c|--cgroup <path>]\n"
    "        [-b|--bpffs <path>]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"bpffs", 'b', "/sys/fs/bpf", 0, "BPF filesystem path"},
    {"iface", 'i', "eth0", 0, "Network Interface name"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    struct env *env = state->input;

    switch (key) {
    case 'v':
        env->verbose = true;
        break;
    case 'b':
        env->bpffs = arg;
        break;
    case 'i':
        env->iface = arg;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;

    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

void print_env_maybe()
{
    if (!env.verbose)
        return;

    printf("#### ENV\n");
    printf("%-15s : %s\n", "bpffs", env.bpffs);
    printf("%-15s : %s\n", "iface", env.iface);
    printf("%-15s : %s\n", "verbose", env.verbose ? "true" : "false");
    printf("####\n");
}

int main(int argc, char **argv)
{
    struct mb_tc_bpf *skel;
    int err, egress_fd, ingress_fd, ifindex = -1;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, &env);
    if (err) {
        fprintf(stderr, "parsing arguments failed with error: %d\n", err);
        return err;
    }

    print_env_maybe();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    (&open_opts)->pin_root_path = strdup(env.bpffs);

    skel = mb_tc_bpf__open_opts(&open_opts);
    err = libbpf_get_error(skel);
    if (err) {
        fprintf(stderr, "opening tc program failed with error: %d\n", err);
        return err;
    }

    err = mb_tc_bpf__load(skel);
    if (err) {
        printf("loading program skeleton failed with error: %d\n", err);
        mb_tc_bpf__destroy(skel);
        return err;
    }

    ifindex = if_nametoindex(env.iface);
    if (ifindex < 1) {
        fprintf(stderr, "trying to map interface's index (%u) to name failed\n",
                ifindex);
        mb_tc_bpf__destroy(skel);
        return 1;
    }

    ingress_fd = bpf_program__fd(skel->progs.mb_tc_ingress);
    if (ingress_fd < 1) {
        fprintf(stderr, "ingress program fd is smaller than 0: %d\n",
                ingress_fd);
        mb_tc_bpf__destroy(skel);
        return 1;
    }

    egress_fd = bpf_program__fd(skel->progs.mb_tc_egress);
    if (ingress_fd < 1) {
        fprintf(stderr, "egress program fd is smaller than 0: %d\n", egress_fd);
        mb_tc_bpf__destroy(skel);
        return 1;
    }

    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS);

    err = bpf_tc_hook_create(&hook);
    if (err < 0) {
        fprintf(stderr, "creating ingress tc hook failed: %s\n",
                strerror(-err));
        close(ingress_fd);
        close(egress_fd);
        mb_tc_bpf__destroy(skel);
        return err;
    }

    LIBBPF_OPTS(bpf_tc_opts, ingress_opts, .priority = 66,
                .prog_fd = ingress_fd);

    err = bpf_tc_attach(&hook, &ingress_opts);
    if (err < 0) {
        fprintf(stderr, "attaching ingress tc program failed: %s\n",
                strerror(-err));
        close(ingress_fd);
        close(egress_fd);
        mb_tc_bpf__destroy(skel);
        return err;
    }

    LIBBPF_OPTS(bpf_tc_opts, egress_opts, .priority = 66, .prog_fd = egress_fd);

    hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_attach(&hook, &egress_opts);
    if (err < 0) {
        fprintf(stderr, "attaching egress tc program failed: %s\n",
                strerror(-err));
        close(ingress_fd);
        close(egress_fd);
        mb_tc_bpf__destroy(skel);
        return err;
    }

    return 0;
}
