#ifndef __KDBX_LINUX__
#define __KDBX_LINUX__

/* This included from include/linux/printk.h */

#include <asm/ptrace.h>

#define KDBX_TRAP_FATAL     1    /* trap is fatal. can't resume from kdb */
#define KDBX_TRAP_NONFATAL  2    /* can resume from kdb */
#define KDBX_TRAP_KDBSTACK  3    /* to debug kdb itself. dump kdb stack */

struct kvm_vcpu;
struct vhost_dev;

extern int earlykdbx;
extern volatile int kdbx_session_begun;

void kdbxp(char *fmt, ...);
void kdbx_init(char *boot_command_line);
int kdbx_handle_trap_entry(int vector, const struct pt_regs *regs1);
int kdbx_handle_guest_trap(int vector, struct kvm_vcpu *vcpu);
void kdbx_trap_immed(int reason);      /* fatal, non-fatal, kdb stack etc... */
int kdbx_keyboard(struct pt_regs *regs);
void kdbxmain_fatal(struct pt_regs *, int);
ulong kdbx_usecs(void);
void kdbx_switch_to_tty(void);
void mukchk(unsigned long);
int mukadd(int i, uint *p);
ulong mukaddl(int i, ulong *p);

void kdbx_do_nmi(struct pt_regs *regs, int err_code);
void kdbx_dump_uart(void);
void kdbx_show_stack(struct pt_regs *regs, pid_t pid);
void kdbx_print_regs(struct pt_regs *regs);
int kdbx_kernel_printk(char *fmt, va_list args);
void kdbx_sav_vhost_dev(struct vhost_dev *dev, char *type);
extern char *kdbx_addr2sym(pid_t, ulong, char *, int);


void kdbxtrc(uint, uint, uint64_t, uint64_t, uint64_t);

#endif /* __KDBX_LINUX__ */
