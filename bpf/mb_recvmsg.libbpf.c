#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "mb_recvmsg.skel.h"

static struct env {
    bool verbose;
    char *cgroups_path;
    char *bpffs;
    char *tc_globals_path;
} env;

const char *argp_program_version = "mb_recvmsg 0.0";
const char *argp_program_bug_address = "<bart.smykla@konghq.com>";
const char argp_program_doc[] =
    "BPF mb_recvmsg demo application.\n"
    "\n"
    "It traces process start and exits and shows associated \n"
    "information (filename, process duration, PID and PPID, etc).\n"
    "\n"
    "USAGE: ./mb_recvmsg [-v]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"cgroup", 'c', "/sys/fs/cgroup", 0, "cgroup path"},
    {"bpffs", 'b', "/sys/fs/bpf", 0, "BPF filesystem path"},
    {"tc_globals_path", 't', "/sys/fs/bpf/tc/globals", 0, "TC globals pash"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    struct env *env = state->input;

    switch (key) {
    case 'v':
        env->verbose = true;
        break;
    case 'c':
        env->cgroups_path = arg;
        break;
    case 'b':
        env->bpffs = arg;
        break;
    case 't':
        env->tc_globals_path = arg;
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
    printf("%-15s : %s\n", "cgroupspath", env.cgroups_path);
    printf("%-15s : %s\n", "bpffs", env.bpffs);
    printf("%-15s : %s\n", "tc_globals_path", env.tc_globals_path);
    printf("%-15s : %s\n", "verbose", env.verbose ? "true" : "false");
    printf("####\n");
}

int main(int argc, char **argv)
{
    struct mb_recvmsg_bpf *skel;
    int err;
    int cgroup_fd;
    int prog_fd;

    env.cgroups_path = "/sys/fs/cgroup";
    env.bpffs = "/run/kuma/bpf";
    env.tc_globals_path = concat(env.bpffs, "/tc/globals");

    char *prog_pin_path = concat(env.bpffs, "/recvmsg");

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

    /* If program is already pinned, skip as it's probably already attached */
    if (access(prog_pin_path, F_OK) == 0) {
        printf("found pinned program %s - skipping\n", prog_pin_path);
        return 0;
    }

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    (&open_opts)->pin_root_path = strdup(env.bpffs);

    skel = mb_recvmsg_bpf__open_opts(&open_opts);
    err = libbpf_get_error(skel);
    if (err) {
        printf("opening program failed with error: %d\n", err);
        return err;
    }

    err = mb_recvmsg_bpf__load(skel);
    if (err) {
        printf("loading program skeleton failed with error: %d\n", err);
        mb_recvmsg_bpf__destroy(skel);
        return err;
    }

    err = bpf_program__pin(skel->progs.mb_recvmsg4 , prog_pin_path);
    if (err) {
        printf("pinning mb_recvmsg4 program to %s failed with error: %d\n",
               prog_pin_path, err);
        mb_recvmsg_bpf__destroy(skel);
        return err;
    }

    cgroup_fd = open(env.cgroups_path, O_RDONLY);
    if (cgroup_fd == -1) {
        printf("opening cgroup %s failed\n", env.cgroups_path);
        mb_recvmsg_bpf__destroy(skel);
        return 1;
    }

    err = bpf_prog_attach(bpf_program__fd(skel->progs.mb_recvmsg4),
                          cgroup_fd, BPF_CGROUP_UDP4_RECVMSG, 0);
    if (err) {
        printf("attaching mb_recvmsg4 program failed with error: %d\n", err);
        close(cgroup_fd);
        mb_recvmsg_bpf__destroy(skel);
        return err;
    }

    return 0;
}
