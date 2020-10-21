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

/* kdbx interfaces in linux files */
#ifdef CONFIG_KDBX_FOR_XEN_DOM0
extern void kdbx_dump_guest_evtchn(void);
#endif
extern void kdbx_dump_timer_queues(void);
extern void kdbx_cpu_flush_vmcs(int cpu);
extern void kdbx_curr_cpu_flush_vmcs(void);
extern void kdbx_dump_vmcs(struct kvm_vcpu *);
extern void kdbx_dump_vmcb(int, int);
extern void kdbx_display_vvmx(struct kvm_vcpu *vp);
extern ulong kdbx_get_vmcs_field(struct kvm_vcpu *vp, uint field);
extern void kdbx_ret_curr_vcpu_info(struct kvm_vcpu **vpp, struct vmcs **vmcspp,
                                    struct vmcs **vmxapp);
void kvm_disp_ioeventfds(struct kvm *kp);


/* linux interfaces used by kdbx */
extern unsigned long address_lookup(char *);
extern int get_ept_level(struct kvm_vcpu *vcpu);
int dom0_read_console(uint32_t vtermno, char *buf, int len);
int dom0_write_console(uint32_t vtermno, const char *str, int len);


/* kdbx globals */
extern volatile int kdbx_sys_crash;
extern volatile kdbx_cpu_cmd_t kdbx_cpu_cmd[NR_CPUS];
extern volatile int kdbx_trcon;

/* kdbx interfaces */
extern void kdbx_init_cmdtab(void);
extern void kdbx_do_cmds(struct pt_regs *);
extern int kdbx_check_sw_bkpts(struct pt_regs *);
extern int kdbx_check_watchpoints(struct pt_regs *);
extern void kdbx_do_watchpoints(kdbva_t, int, int);
extern void kdbx_install_watchpoints(void);
extern void kdbx_clear_wps(int);
extern kdbma_t kdbx_rd_dbgreg(int);
extern void kdbx_init_io(char *cmdline);
extern int kdbx_guest_mode(struct pt_regs *regs);
extern ulong kdbx_get_hvm_field(struct kvm_vcpu *vp, uint field);

extern char *kdbx_get_input(char *);
extern void kdbx_clear_prev_cmd(void);
extern void kdbx_toggle_dis_syntax(void);
extern int kdbx_check_call_instr(kdbva_t, pid_t gpid);
extern void kdbx_display_pc(struct pt_regs *regs);
extern kdbva_t kdbx_print_instr(kdbva_t, long, pid_t);
extern int kdbx_read_mmem(kdbva_t, kdbbyt_t *, int);
extern int kdbx_read_mem(kdbva_t, kdbbyt_t *, int, struct kvm_vcpu *);
extern int kdbx_write_mem(kdbva_t, kdbbyt_t *, int, struct kvm_vcpu *);
extern int kdbx_walk_pt(ulong addr, struct kvm_vcpu *vp);
extern int kdbx_is_addr_guest_text(ulong addr, pid_t gpid);
extern kdbva_t kdbx_guest_sym2addr(char *p, pid_t gpid);
extern char *kdbx_guest_addr2sym(unsigned long addr, pid_t gpid, ulong *offsp);
extern void kdbx_sav_guest_syminfo(pid_t, ulong, ulong, ulong, ulong, ulong,
                                   ulong, ulong);
extern int kdbx_guest_bitness(pid_t gpid);
extern struct kvm_vcpu *kdbx_pid_to_vcpu(pid_t pid, int pr_err);
extern void kdbx_vcpu_to_ptregs(struct kvm_vcpu *vp, struct pt_regs *regs);
extern void kdbx_ptregs_to_vcpu(struct kvm_vcpu *vp, struct pt_regs *regs);
extern pid_t kdbx_pid2tgid(pid_t pid);
extern int kdbx_guest_sym_loaded(pid_t gpid);

extern void kdbx_install_all_swbp(void);
extern void kdbx_uninstall_all_swbp(void);
extern int kdbx_swbp_exists(void);
extern void kdbx_flush_swbp_table(void);
extern void kdbx_prnt_addr2sym(pid_t, kdbva_t, char *);
extern void kdbx_nmi_pause_cpus(struct cpumask);
extern ulong kdbx_p2m(struct kvm_vcpu *vp, ulong gfn);

extern void kdbx_trczero(void);
extern void kdbx_trcp(void);

#endif /* !_KDBPROTO_H */
