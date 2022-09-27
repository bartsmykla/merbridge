
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

#include "mb_netns_cleanup.skel.h"

static struct env {
    bool verbose;
    char *bpffs;
} env;

const char *argp_program_version = "mb_recvmsg 0.1";
const char argp_program_doc[] =
    "BPF mb_netns_cleanup loader.\n"
    "\n"
    "USAGE: ./mb_netns_cleanup [-v|--verbose] [-b|--bpffs <path>]\n";

static const struct argp_option opts[] = {
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {"bpffs", 'b', "PATH", 0, "BPF filesystem path"},
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
    printf("%-15s : %s\n", "verbose", env.verbose ? "true" : "false");
    printf("####\n");
}

const char RELATIVE_PIN_PATH[] = "/netns_cleanup";

int main(int argc, char **argv)
{
    struct mb_netns_cleanup_bpf *skel;
    int err;

    // default values
    env.bpffs = "/sys/fs/bpf";

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, &env);
    if (err) {
        fprintf(stderr, "parsing arguments failed with error: %d\n", err);
        return err;
    }

    size_t len = strlen(env.bpffs) + sizeof(RELATIVE_PIN_PATH) + 6;
    char *prog_pin_path = (char *)malloc(len);
    char *link_pin_path = (char *)malloc(len);
    
    snprintf(prog_pin_path, len, "%s%s_prog", env.bpffs, RELATIVE_PIN_PATH);
    snprintf(link_pin_path, len, "%s%s_link", env.bpffs, RELATIVE_PIN_PATH);

    print_env_maybe();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* If program is already pinned, skip as it's probably already attached */
    if (access(prog_pin_path, F_OK) == 0) {
        printf("found pinned program %s - skipping\n", prog_pin_path);
        free(prog_pin_path);
        free(link_pin_path);
        return 0;
    }

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    (&open_opts)->pin_root_path = strdup(env.bpffs);

    skel = mb_netns_cleanup_bpf__open_opts(&open_opts);
    err = libbpf_get_error(skel);
    if (err) {
        fprintf(stderr,
                "opening mb_netns_cleanup objects failed with error: %d\n",
                err);
        free(prog_pin_path);
        free(link_pin_path);
        return err;
    }

    err = mb_netns_cleanup_bpf__load(skel);
    if (err) {
        fprintf(stderr,
                "loading mb_netns_cleanup skeleton failed with error: %d\n",
                err);
        mb_netns_cleanup_bpf__destroy(skel);
        free(prog_pin_path);
        free(link_pin_path);
        return err;
    }

    err = mb_netns_cleanup_bpf__attach(skel);
    if (err) {
        fprintf(stderr,
                "attaching mb_netns_cleanup program failed with error: %d\n",
                err);
        mb_netns_cleanup_bpf__destroy(skel);
        free(prog_pin_path);
        free(link_pin_path);
        return err;
    }

    err = bpf_program__pin(skel->progs.net_ns_net_exit, prog_pin_path);
    if (err) {
        fprintf(stderr,
                "pinning net_ns_net_exit program to %s failed with error: %d\n",
                prog_pin_path, err);
        mb_netns_cleanup_bpf__destroy(skel);
        free(prog_pin_path);
        free(link_pin_path);
        return err;
    }

    err = bpf_link__pin(skel->links.net_ns_net_exit, link_pin_path);
    if (err) {
        fprintf(stderr,
                "pinning net_ns_net_exit link to %s failed with error: %d\n",
                link_pin_path, err);
        mb_netns_cleanup_bpf__destroy(skel);
        free(prog_pin_path);
        free(link_pin_path);
        return err;
    }

    free(prog_pin_path);
    free(link_pin_path);

    return 0;
}
