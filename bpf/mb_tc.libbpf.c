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
    char *tc_globals_path;
    char *iface;
} env;

const char *argp_program_version = "mb_tc 0.0";
const char *argp_program_bug_address = "<bart.smykla@konghq.com>";
const char argp_program_doc[] =
    "BPF mb_tc demo application.\n"
    "\n"
    "It traces process start and exits and shows associated \n"
    "information (filename, process duration, PID and PPID, etc).\n"
    "\n"
    "USAGE: ./mb_tc [-v]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"bpffs", 'b', "/sys/fs/bpf", 0, "BPF filesystem path"},
    {"tc_globals_path", 't', "/sys/fs/bpf/tc/globals", 0, "TC globals pash"},
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
    case 't':
        env->tc_globals_path = arg;
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

char *concat(const char *s1, const char *s2)
{
    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);
    char *result = malloc(len1 + len2 + 1); // +1 for the null-terminator

    // in real code you would check for errors in malloc here
    memcpy(result, s1, len1);
    memcpy(result + len1, s2, len2 + 1); // +1 to copy the null-terminator

    return result;
}

void print_env_maybe()
{
    if (!env.verbose)
        return;

    printf("#### ENV\n");
    printf("%-15s : %s\n", "bpffs", env.bpffs);
    printf("%-15s : %s\n", "tc_globals_path", env.tc_globals_path);
    printf("%-15s : %s\n", "iface", env.iface);
    printf("%-15s : %s\n", "verbose", env.verbose ? "true" : "false");
    printf("####\n");
}

int main(int argc, char **argv)
{
    struct mb_tc_bpf *skel;
    int err;
    int egress_fd, ingress_fd, ifindex = -1;

    env.bpffs = "/run/kuma/bpf";
    env.iface = "eth0";
    env.tc_globals_path = concat(env.bpffs, "/tc/globals");

    // char *prog_ingress_pin_path = concat(env.bpffs, "/tc_ingress");
    // char *prog_egress_pin_path = concat(env.bpffs, "/tc_egress");
    char *local_pod_ips_map_pin_path =
        concat(env.tc_globals_path, "/local_pod_ips");

    char *pair_orig_dst_map_pin_path =
        concat(env.tc_globals_path, "/pair_orig_dst");

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, &env);
    if (err) {
        printf("parsing arguments failed with error: %d\n", err);
        return err;
    }

    print_env_maybe();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // /* If program is already pinned, skip as it's probably already attached */
    // if (access(prog_ingress_pin_path, F_OK) == 0) {
    //     printf("found pinned ingress program %s - skipping\n", prog_ingress_pin_path);
    //     return 0;
    // }

    // /* If program is already pinned, skip as it's probably already attached */
    // if (access(prog_egress_pin_path, F_OK) == 0) {
    //     printf("found pinned egress program %s - skipping\n", prog_egress_pin_path);
    //     return 0;
    // }

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    (&open_opts)->pin_root_path = strdup(env.bpffs);

    skel = mb_tc_bpf__open_opts(&open_opts);
    err = libbpf_get_error(skel);
    if (err) {
        printf("opening program failed with error: %d\n", err);
        return err;
    }

    err = bpf_map__set_pin_path(skel->maps.local_pod_ips,
                                local_pod_ips_map_pin_path);

    err = bpf_map__set_pin_path(skel->maps.pair_orig_dst,
                                pair_orig_dst_map_pin_path);
    if (err) {
        printf("setting pin path (%s) to local_pod_ips map failed with error: "
               "%d\n",
               local_pod_ips_map_pin_path, err);
        mb_tc_bpf__destroy(skel);
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
        printf("if_nametoindex(env.iface) failed\n");
        mb_tc_bpf__destroy(skel);
        return 1;
    }

    ingress_fd = bpf_program__fd(skel->progs.mb_tc_ingress);
    if (ingress_fd < 1) {
        printf("ingress_fd: %d\n", ingress_fd);
        mb_tc_bpf__destroy(skel);
        return 1;
    }

    egress_fd = bpf_program__fd(skel->progs.mb_tc_egress);
    if (ingress_fd < 1) {
        printf("egress_fd: %d\n", egress_fd);
        mb_tc_bpf__destroy(skel);
        return 1;
    }

    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
                .attach_point = BPF_TC_INGRESS);

    err = bpf_tc_hook_create(&hook);
    if (err < 0) {
        fprintf(stderr, "Error: bpf_tc_hook_create: %s\n", strerror(-err));
        close(ingress_fd);
        close(egress_fd);
        mb_tc_bpf__destroy(skel);
        return err;
    }

    LIBBPF_OPTS(bpf_tc_opts, ingress_opts, .priority = 66,
                .prog_fd = ingress_fd);

    err = bpf_tc_attach(&hook, &ingress_opts);
    if (err < 0) {
        fprintf(stderr, "Error: bpf_tc_attach ingress: %s\n", strerror(-err));
        close(ingress_fd);
        close(egress_fd);
        mb_tc_bpf__destroy(skel);
        return err;
    }

    // err = bpf_program__pin(skel->progs.mb_tc_ingress, prog_ingress_pin_path);
    // if (err) {
    //     printf("pinning mb_tc ingress program to %s failed with error: %d\n",
    //            prog_ingress_pin_path, err);
    //     close(ingress_fd);
    //     close(egress_fd);
    //     mb_tc_bpf__destroy(skel);
    //     return err;
    // }

    LIBBPF_OPTS(bpf_tc_opts, egress_opts, .priority = 66, .prog_fd = egress_fd);

    hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_attach(&hook, &egress_opts);
    if (err < 0) {
        fprintf(stderr, "Error: bpf_tc_attach egress: %s\n", strerror(-err));
        close(ingress_fd);
        close(egress_fd);
        mb_tc_bpf__destroy(skel);
        return err;
    }

    // err = bpf_program__pin(skel->progs.mb_tc_egress, prog_egress_pin_path);
    // if (err) {
    //     printf("pinning mb_tc egress program to %s failed with error: %d\n",
    //            prog_egress_pin_path, err);
    //     mb_tc_bpf__destroy(skel);
    //     return err;
    // }

    return 0;
}
