/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#ifndef _KDBPROTO_H
#define _KDBPROTO_H

struct vmcs;

/* linux interfaces use by kdb or kdb interfaces in linux files */
extern void kdb_dump_timer_queues(void);
extern void kdb_time_resume(int);
extern void kdb_print_sched_info(void);
extern void kdbx_cpu_flush_vmcs(int cpu);
extern void kdbx_curr_cpu_flush_vmcs(void);
extern void kdbx_dump_vmcs(struct kvm_vcpu *);
extern void kdbx_dump_vmcb(int, int);
extern unsigned long address_lookup(char *);
extern void kdb_prnt_guest_mapped_irqs(void);
extern void kdbx_display_vvmx(struct kvm_vcpu *vp);
extern ulong kdbx_vmx_get_host_sp(struct kvm_vcpu *vp);
extern ulong kdbx_get_vmcs_field(struct kvm_vcpu *vp, uint field);
extern void kdbx_ret_curr_vcpu_info(struct kvm_vcpu **vpp, struct vmcs **vmcspp,
                                    struct vmcs **vmxapp);
extern int get_ept_level(struct kvm_vcpu *vcpu);

/* kdb globals */
extern kdbtab_t *kdb_cmd_tbl;
extern char kdb_prompt[32];
extern volatile int kdb_sys_crash;
extern volatile kdb_cpu_cmd_t kdb_cpu_cmd[NR_CPUS];
extern volatile int kdb_trcon;

/* kdb interfaces */
extern void __init kdb_io_init(void);
extern void kdb_init_cmdtab(void);
extern void kdb_do_cmds(struct pt_regs *);
extern int kdb_check_sw_bkpts(struct pt_regs *);
extern int kdb_check_watchpoints(struct pt_regs *);
extern void kdb_do_watchpoints(kdbva_t, int, int);
extern void kdb_install_watchpoints(void);
extern void kdb_clear_wps(int);
extern kdbma_t kdb_rd_dbgreg(int);
extern void kdbx_init_console(char *cmdline);
extern int kdb_guest_mode(struct pt_regs *regs);
extern ulong kdb_get_hvm_field(struct kvm_vcpu *vp, uint field);

extern char *kdb_get_cmdline(char *);
extern void kdb_clear_prev_cmd(void);
extern void kdb_toggle_dis_syntax(void);
extern int kdb_check_call_instr(kdbva_t, pid_t gpid);
extern void kdb_display_pc(struct pt_regs *regs);
extern kdbva_t kdb_print_instr(kdbva_t, long, pid_t);
extern int kdb_read_mmem(kdbva_t, kdbbyt_t *, int);
extern int kdb_read_mem(kdbva_t, kdbbyt_t *, int, struct kvm_vcpu *);
extern int kdb_write_mem(kdbva_t, kdbbyt_t *, int, struct kvm_vcpu *);
extern int kdb_write_bp(kdbva_t, kdbbyt_t *, int);
extern int kdb_is_addr_guest_text(ulong addr, pid_t gpid);
extern kdbva_t kdb_guest_sym2addr(char *p, pid_t gpid);
extern char *kdb_guest_addr2sym(unsigned long addr, pid_t gpid, ulong *offsp);
extern void kdb_sav_guest_syminfo(pid_t, long, long, long, long, long);
extern int kdb_guest_bitness(pid_t gpid);
extern struct kvm_vcpu *kdb_pid_to_vcpu(pid_t pid, int pr_err);
extern void kdb_vcpu_to_ptregs(struct kvm_vcpu *vp, struct pt_regs *regs);
extern void kdb_ptregs_to_vcpu(struct kvm_vcpu *vp, struct pt_regs *regs);
extern pid_t kdb_pid2tgid(pid_t pid);
extern void kdb_print_regs(struct pt_regs *regs);
extern void kdb_show_stack(struct pt_regs *regs, pid_t pid);
extern int kdb_guest_sym_loaded(pid_t gpid);

extern void kdb_install_all_swbp(void);
extern void kdb_uninstall_all_swbp(void);
extern int kdb_swbp_exists(void);
extern void kdb_flush_swbp_table(void);
extern void kdb_prnt_addr2sym(pid_t, kdbva_t, char *);
extern void kdb_nmi_pause_cpus(struct cpumask);
extern ulong kdb_p2m(ulong gfn, struct kvm_vcpu *vp);

extern void kdb_trczero(void);
void kdb_trcp(void);

#endif /* !_KDBPROTO_H */
