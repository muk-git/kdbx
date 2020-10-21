/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
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

/* hypervisor interfaces use by kdb or kdb interfaces in xen files */
extern void console_putc(char);
extern int console_getc(void);
extern void show_trace(struct cpu_user_regs *);
extern void kdb_dump_timer_queues(void);
extern void kdb_time_resume(int);
extern void kdb_print_sched_info(void);
extern void kdb_curr_cpu_flush_vmcs(void);
extern unsigned long address_lookup(char *);
extern void (*direct_apic_vector[NR_VECTORS])(struct cpu_user_regs *);
extern void kdb_print_guest_irq_info(int);
extern void kdb_prnt_guest_mapped_irqs(void);
extern void show_stack(struct cpu_user_regs *regs);

/* kdb globals */
extern kdbtab_t *kdb_cmd_tbl;
extern char kdb_prompt[32];
extern volatile int kdb_sys_crash;
extern volatile kdb_cpu_cmd_t kdb_cpu_cmd[NR_CPUS];
extern volatile int kdb_trcon;

/* kdb interfaces */
extern void __init kdb_io_init(void);
extern void kdb_init_cmdtab(void);
extern void kdb_do_cmds(struct cpu_user_regs *);
extern int kdb_check_sw_bkpts(struct cpu_user_regs *);
extern int kdb_check_watchpoints(struct cpu_user_regs *);
extern void kdb_do_watchpoints(kdbva_t, int, int);
extern void kdb_install_watchpoints(void);
extern void kdb_clear_wps(int);
extern kdbma_t kdb_rd_dbgreg(int);



extern char *kdb_get_cmdline(char *);
extern void kdb_clear_prev_cmd(void);
extern void kdb_toggle_dis_syntax(void);
extern int kdb_check_call_instr(domid_t, kdbva_t);
extern void kdb_display_pc(struct cpu_user_regs *);
extern kdbva_t kdb_print_instr(kdbva_t, long, domid_t);
extern int kdb_read_mmem(kdbva_t, kdbbyt_t *, int);
extern int kdb_read_mem(kdbva_t, kdbbyt_t *, int, domid_t);
extern int kdb_write_mem(kdbva_t, kdbbyt_t *, int, domid_t);

extern void kdb_install_all_swbp(void);
extern void kdb_uninstall_all_swbp(void);
extern int kdb_swbp_exists(void);
extern void kdb_flush_swbp_table(void);
extern int kdb_is_addr_guest_text(kdbva_t, int);
extern kdbva_t kdb_guest_sym2addr(char *, domid_t);
extern char *kdb_guest_addr2sym(unsigned long, domid_t, ulong *);
extern void kdb_prnt_addr2sym(domid_t, kdbva_t, char *);
extern void kdb_sav_dom_syminfo(domid_t, long, long, long, long, long);
extern int kdb_guest_bitness(domid_t);
extern void kdb_nmi_pause_cpus(cpumask_t);

void kdb_clear_stats(void);
extern void kdb_trczero(void);
void kdb_trcp(void);



#endif /* !_KDBPROTO_H */
