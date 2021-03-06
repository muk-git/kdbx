#ifndef __KDBX_LINUX__
#define __KDBX_LINUX__

/* This included from include/linux/printk.h */

#include <asm/ptrace.h>

#define KDBX_TRAP_FATAL     1    /* trap is fatal. can't resume from kdb */
#define KDBX_TRAP_NONFATAL  2    /* can resume from kdb */
#define KDBX_TRAP_KDBSTACK  3    /* to debug kdb itself. dump kdb stack */

#define kdbx_ccpu (raw_smp_processor_id())

struct kvm_vcpu;
struct vhost_dev;

extern int earlykdbx;
extern volatile int kdbx_session_begun;

char *kdbx_hostsym(void *addr);
void kdbxp(char *fmt, ...);
void kdbx_init(char *boot_command_line);
int kdbx_handle_trap_entry(int vector, const struct pt_regs *regs1);
int kdbx_handle_guest_trap(int vector, struct kvm_vcpu *vcpu);
void kdbx_trap_immed(int reason);      /* fatal, non-fatal, kdb stack etc... */
int kdbx_keyboard(struct pt_regs *regs);
void kdbxmain_fatal(struct pt_regs *, int);
ulong kdbx_tsc_to_ns(ulong delta);
ulong kdbx_tsc_to_us(ulong delta);
ulong kdbx_usecs(void);
void kdbx_switch_to_tty(void);
void mukchk(unsigned long);
int mukadd(int i, uint *p);
ulong mukaddl(int i, ulong *p);
int kdbx_excp_fixup(struct pt_regs *regs, int vector);

void kdbx_do_nmi(struct pt_regs *regs);
void kdbx_dump_uart(void);
void kdbx_show_stack(struct pt_regs *regs, pid_t pid, int kstack, int max);
void kdbx_print_regs(struct pt_regs *regs);
void kdbx_sav_vhost_dev(struct vhost_dev *dev, char *type);
char *kdbx_addr2sym(pid_t, ulong, char *, int);
ulong kdbx_rsp(void);
void kdbxtrc(uint, uint, uint64_t, uint64_t, uint64_t);

#endif /* __KDBX_LINUX__ */
