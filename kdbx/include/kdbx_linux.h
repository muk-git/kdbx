#ifndef __KDBX_LINUX__
#define __KDBX_LINUX__

/* This included from include/linux/printk.h */

#include <asm/ptrace.h>

#define KDBX_TRAP_FATAL     1    /* trap is fatal. can't resume from kdb */
#define KDBX_TRAP_NONFATAL  2    /* can resume from kdb */
#define KDBX_TRAP_KDBSTACK  3    /* to debug kdb itself. dump kdb stack */

struct kvm_vcpu;

extern int earlykdbx;
extern volatile int kdbx_session_begun;

void kdbxp(const char *fmt, ...);
void kdbx_init(char *boot_command_line);
int kdbx_handle_trap_entry(int vector, const struct pt_regs *regs1);
int kdbx_handle_guest_trap(int vector, struct kvm_vcpu *vcpu);
void kdbx_trap_immed(int reason);      /* fatal, non-fatal, kdb stack etc... */
int kdbx_keyboard(struct pt_regs *regs);
void kdbxmain_fatal(struct pt_regs *, int);
void mukchk(unsigned long);

#endif /* __KDBX_LINUX__ */
