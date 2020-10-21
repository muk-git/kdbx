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

#include "include/kdbinc.h"

static int kdbmain(kdb_reason_t, struct cpu_user_regs *);
static int kdbmain_fatal(struct cpu_user_regs *, int);
static const char *kdb_gettrapname(int);

/* ======================== GLOBAL VARIABLES =============================== */
/* All global variables used by KDB must be defined here only. Module specific
 * static variables must be declared in respective modules.
 */
kdbtab_t *kdb_cmd_tbl;
char kdb_prompt[32];

volatile kdb_cpu_cmd_t kdb_cpu_cmd[NR_CPUS];
cpumask_t kdb_cpu_traps;           /* bit per cpu to tell which cpus hit int3 */

#if 0
#ifndef NDEBUG
    #error KDB is not supported on debug xen. Turn debug off
#endif
#endif

volatile int kdb_init_cpu = -1;           /* initial kdb cpu */
volatile int kdb_session_begun = 0;       /* active kdb session? */
volatile int kdb_enabled = 1;             /* kdb enabled currently? */
volatile int kdb_sys_crash = 0;           /* are we in crashed state? */
volatile int kdbdbg = 0;                  /* to debug kdb itself */

static volatile int kdb_trap_immed_reason = 0;   /* reason for immed trap */

static cpumask_t kdb_fatal_cpumask;       /* which cpus in fatal path */

/* return index of first bit set in val. if val is 0, retval is undefined */
static inline unsigned int kdb_firstbit(unsigned long val)
{
    __asm__ ( "bsf %1,%0" : "=r" (val) : "r" (val), "0" (BITS_PER_LONG) );
    return (unsigned int)val;
}

static void 
kdb_dbg_prnt_ctrps(char *label, int ccpu)
{
    int i;
    if (!kdbdbg)
        return;

    if (label || *label)
        kdbp("%s ", label);
    if (ccpu != -1)
        kdbp("ccpu:%d ", ccpu);
    kdbp("cputrps:");
    for (i=sizeof(kdb_cpu_traps)/sizeof(kdb_cpu_traps.bits[0]) - 1; i >=0; i--)
        kdbp(" %lx", kdb_cpu_traps.bits[i]);
    kdbp("\n");
}

/* 
 * Hold this cpu. Don't disable until all CPUs in kdb to avoid IPI deadlock 
 */
static void
kdb_hold_this_cpu(int ccpu, struct cpu_user_regs *regs)
{
    KDBGP("ccpu:%d hold. cmd:%x\n", kdb_cpu_cmd[ccpu]);
    do {
        for(; kdb_cpu_cmd[ccpu] == KDB_CPU_PAUSE; cpu_relax());
        KDBGP("ccpu:%d hold. cmd:%x\n", kdb_cpu_cmd[ccpu]);

        if (kdb_cpu_cmd[ccpu] == KDB_CPU_DISABLE) {
            local_irq_disable();
            kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_DO_VMEXIT) {
            kdb_curr_cpu_flush_vmcs();
            kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_SHOWPC) {
            kdbp("[%d]", ccpu);
            kdb_display_pc(regs);
            kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
    } while (kdb_cpu_cmd[ccpu] == KDB_CPU_PAUSE);     /* No goto, eh! */
    KDBGP1("un hold: ccpu:%d cmd:%d\n", ccpu, kdb_cpu_cmd[ccpu]);
}

/*
 * Pause this cpu while one CPU does main kdb processing. If that CPU does
 * a "cpu switch" to this cpu, this cpu will become the main kdb cpu. If the
 * user next does single step of some sort, this function will be exited,
 * and this cpu will come back into kdb via kdb_handle_trap_entry function.
 */
static void 
kdb_pause_this_cpu(struct cpu_user_regs *regs, void *unused)
{
    kdbmain(KDB_REASON_PAUSE_IPI, regs);
}

/* pause other cpus via an IPI. Note, disabled CPUs can't receive IPIs until
 * enabled */
static void
kdb_smp_pause_cpus(void)
{
    int cpu, wait_count = 0;
    int ccpu = smp_processor_id();      /* current cpu */
    cpumask_t cpumask = cpu_online_map;

    cpumask_clear_cpu(smp_processor_id(), &cpumask);
    for_each_cpu(cpu, &cpumask)
        if (kdb_cpu_cmd[cpu] != KDB_CPU_INVAL) {
            kdbp("KDB: won't pause cpu:%d, cmd[cpu]=%d\n",cpu,kdb_cpu_cmd[cpu]);
            cpumask_clear_cpu(cpu, &cpumask);
        }
    KDBGP("ccpu:%d will pause cpus. mask:0x%lx\n", ccpu, cpumask.bits[0]);
    on_selected_cpus(&cpumask, (void (*)(void *))kdb_pause_this_cpu, 
                     "XENKDB", 0);
    mdelay(300);                     /* wait a bit for other CPUs to stop */
    while(wait_count++ < 10) {
        int bummer = 0;
        for_each_cpu(cpu, &cpumask)
            if (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE)
                bummer = 1;
        if (!bummer)
            break;
        kdbp("ccpu:%d trying to stop other cpus...\n", ccpu);
        mdelay(100);  /* wait 100 ms */
    };
    for_each_cpu(cpu, &cpumask)          /* now check who is with us */
        if (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE)
            kdbp("Bummer cpu %d not paused. ccpu:%d\n", cpu,ccpu);
        else {
            kdb_cpu_cmd[cpu] = KDB_CPU_DISABLE;  /* tell it to disable ints */
            while (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE);
        }
}

/* 
 * Do once per kdb session:  A kdb session lasts from 
 *    keybord/HWBP/SWBP till KDB_CPU_INSTALL_BP is done. Within a session,
 *    user may do several cpu switches, single step, next instr,  etc..
 *
 * DO: 1. pause other cpus if they are not already. they would already be 
 *        if we are in single step mode
 *     2. watchdog_disable() 
 *     3. uninstall all sw breakpoints so that user doesn't see them
 */
static void
kdb_begin_session(void)
{
    if (!kdb_session_begun) {
        kdb_session_begun = 1;
        kdb_smp_pause_cpus();
        local_irq_disable();
        watchdog_disable();
        kdb_uninstall_all_swbp();
    }
}

static void
kdb_smp_unpause_cpus(int ccpu)
{
    int cpu;

    int wait_count = 0;
    cpumask_t cpumask = cpu_online_map;

    cpumask_clear_cpu(smp_processor_id(), &cpumask);

    KDBGP("kdb_smp_unpause_other_cpus(). ccpu:%d\n", ccpu);
    for_each_cpu(cpu, &cpumask)
        kdb_cpu_cmd[cpu] = KDB_CPU_QUIT;

    while(wait_count++ < 10) {
        int bummer = 0;

        for_each_cpu(cpu, &cpumask)
            if (kdb_cpu_cmd[cpu] != KDB_CPU_INVAL)
                bummer = 1;
        if (!bummer)
            break;
        mdelay(90);  /* wait 90 ms, 50 too short on large systems */
    };
    /* now make sure they are all in there */
    for_each_cpu(cpu, &cpumask)
        if (kdb_cpu_cmd[cpu] != KDB_CPU_INVAL)
            kdbp("KDB: cpu %d still paused (cmd==%d). ccpu:%d\n",
                 cpu, kdb_cpu_cmd[cpu], ccpu);
}

/*
 * End of KDB session. 
 *   This is called at the very end. In case of multiple cpus hitting BPs
 *   and sitting on a trap handlers, the last cpu to exit will call this.
 *   - isnstall all sw breakpoints, and purge deleted ones from table.
 *   - clear TF here also in case go is entered on a different cpu after switch
 */
static void
kdb_end_session(int ccpu, struct cpu_user_regs *regs)
{
    ASSERT(cpumask_empty(&kdb_cpu_traps));
    ASSERT(kdb_session_begun);
    kdb_install_all_swbp();
    kdb_flush_swbp_table();
    kdb_install_watchpoints();

    regs->eflags &= ~X86_EFLAGS_TF;
    kdb_cpu_cmd[ccpu] = KDB_CPU_INVAL;
    kdb_time_resume(1);
    kdb_session_begun = 0;      /* before unpause for kdb_install_watchpoints */
    kdb_smp_unpause_cpus(ccpu);
    watchdog_enable();
    KDBGP("end_session:ccpu:%d\n", ccpu);
}

/* 
 * check if we entered kdb because of DB trap. If yes, then check if
 * we caused it or someone else.
 * RETURNS: 0 : not one of ours. hypervisor must handle it. 
 *          1 : #DB for delayed sw bp install. 
 *          2 : this cpu must stay in kdb.
 */
static noinline int
kdb_check_dbtrap(kdb_reason_t *reasp, int ss_mode, struct cpu_user_regs *regs) 
{
    int rc = 2;
    int ccpu = smp_processor_id();

    /* DB excp caused by hw breakpoint or the TF flag. The TF flag is set
     * by us for ss mode or to install breakpoints. In ss mode, none of the
     * breakpoints are installed. Check to make sure we intended BP INSTALL
     * so we don't do it on a spurious DB trap.
     * check for kdb_cpu_traps here also, because each cpu sitting on a trap
     * must execute the instruction without the BP before passing control
     * to next cpu in kdb_cpu_traps.
     */
    if (*reasp == KDB_REASON_DBEXCP && !ss_mode) {
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_INSTALL_BP) {
            if (!cpumask_empty(&kdb_cpu_traps)) {
                int a_trap_cpu = cpumask_first(&kdb_cpu_traps);
                KDBGP("ccpu:%d trapcpu:%d\n", ccpu, a_trap_cpu);
                kdb_cpu_cmd[a_trap_cpu] = KDB_CPU_QUIT;
                *reasp = KDB_REASON_PAUSE_IPI;
                regs->eflags &= ~X86_EFLAGS_TF;  /* hvm: exit handler ss = 0 */
                kdb_init_cpu = -1;
            } else {
                kdb_end_session(ccpu, regs);
                rc = 1;
            }
        } else if (! kdb_check_watchpoints(regs)) {
            rc = 0;                        /* hyp must handle it */
        }
    }
    return rc;
}

/* 
 * Misc processing on kdb entry like displaying PC, adjust IP for sw bp.... 
 */
static void
kdb_main_entry_misc(kdb_reason_t reason, struct cpu_user_regs *regs, 
                    int ccpu, int ss_mode, int enabled)
{
    if (reason == KDB_REASON_KEYBOARD)
        kdbp("\nEnter kdb (cpu:%d reason:%d vcpu=%d domid:%d"
             " eflg:0x%lx irqs:%d)\n", ccpu, reason, current->vcpu_id, 
             current->domain->domain_id, regs->eflags, enabled);
    else if (ss_mode)
        KDBGP1("KDBG: KDB single step mode. ccpu:%d\n", ccpu);

    if (reason == KDB_REASON_BPEXCP && !ss_mode) 
        kdbp("Breakpoint on cpu %d at 0x%lx\n", ccpu, regs->KDBIP);

    /* display the current PC and instruction at it */
    if (reason != KDB_REASON_PAUSE_IPI)
        kdb_display_pc(regs);
    console_start_sync();
}

/* 
 * The MAIN kdb function. All cpus go thru this. IRQ is enabled on entry because
 * a cpu could hit a bp set in disabled code.
 * IPI: Even the main cpu must enable in case another CPU is trying to IPI us.
 *      That way, it would IPI us, then get out and be ready for our pause IPI.
 * IRQs: The reason irqs enable/disable is scattered is because on a typical
 *       system IPIs are constantly going on amongs CPUs in a set of any size. 
 *       As a result,  to avoid deadlock, cpus have to loop enabled, until a 
 *       quorum is established and the session has begun.
 * Step: Intel Vol3B 18.3.1.4 : An external interrupt may be serviced upon
 *       single step. Since, the likely ext timer_interrupt and 
 *       apic_timer_interrupt dont' mess with time data structs, we are prob OK
 *       leaving enabled.
 * Time: Very messy. Most platform timers are readonly, so we can't stop time
 *       in the debugger. We take the only resort, let the TSC and plt run as
 *       normal, upon leaving, "attempt" to bring everybody to current time.
 * kdbcputraps: bit per cpu. each cpu sets it bit in entry.S. The bit is 
 *              reliable because upon traps, Ints are disabled. the bit is set
 *              before Ints are enabled.
 *
 * RETURNS: 0 : kdb was called for event it was not responsible
 *          1 : event owned and handled by kdb 
 */
static int
kdbmain(kdb_reason_t reason, struct cpu_user_regs *regs)
{
    int ccpu = smp_processor_id();                /* current cpu */
    int rc = 1, cmd = kdb_cpu_cmd[ccpu];
    int ss_mode = (cmd == KDB_CPU_SS || cmd == KDB_CPU_NI);
    int delayed_install = (kdb_cpu_cmd[ccpu] == KDB_CPU_INSTALL_BP);
    int enabled = local_irq_is_enabled();

    KDBGP("kdbmain:ccpu:%d rsn:%d eflgs:0x%lx cmd:%d initc:%d irqs:%d "
          "regs:%lx IP:%lx ", ccpu, reason, regs->eflags, cmd, 
          kdb_init_cpu, enabled, regs, regs->KDBIP);
    kdb_dbg_prnt_ctrps("", -1);

    if (!ss_mode && !delayed_install)    /* initial kdb enter */
        local_irq_enable();              /* so we can receive IPI */

    if (!ss_mode && ccpu != kdb_init_cpu && reason != KDB_REASON_PAUSE_IPI) {
        int sz = sizeof(kdb_init_cpu);
        while (__cmpxchg(&kdb_init_cpu, -1, ccpu, sz) != -1)
            for(; kdb_init_cpu != -1; cpu_relax());
    }
    if (kdb_session_begun)
        local_irq_disable();             /* kdb always runs disabled */

    if (reason == KDB_REASON_BPEXCP) {             /* INT 3 */
        cpumask_clear_cpu(ccpu, &kdb_cpu_traps);   /* remove ourself */
        rc = kdb_check_sw_bkpts(regs);
        if (rc == 0) {               /* not one of ours. leave kdb */
            kdb_init_cpu = -1;
            goto out;
        } else if (rc == 1) {        /* one of ours but deleted */
            if (cpumask_empty(&kdb_cpu_traps)) {
                kdb_end_session(ccpu,regs);     
                kdb_init_cpu = -1;
                goto out;
            } else {                 
                /* release another trap cpu, and put ourself in a pause mode */
                int a_trap_cpu = cpumask_first(&kdb_cpu_traps);
                KDBGP("ccpu:%d cmd:%d rsn:%d atrpcpu:%d initcpu:%d\n", ccpu, 
                      kdb_cpu_cmd[ccpu], reason, a_trap_cpu, kdb_init_cpu);
                kdb_cpu_cmd[a_trap_cpu] = KDB_CPU_QUIT;
                reason = KDB_REASON_PAUSE_IPI;
                kdb_init_cpu = -1;
            }
        } else if (rc == 2) {        /* one of ours but condition not met */
                kdb_begin_session();
                if (guest_mode(regs) && !is_pv_vcpu(current) )
                    current->arch.hvm_vcpu.single_step = 1;
                else
                    regs->eflags |= X86_EFLAGS_TF;  
                kdb_cpu_cmd[ccpu] = KDB_CPU_INSTALL_BP;
                goto out;
        }
    }

    /* following will take care of KDB_CPU_INSTALL_BP, and also release
     * kdb_init_cpu. it should not be done twice */
    if ((rc=kdb_check_dbtrap(&reason, ss_mode, regs)) == 0 || rc == 1) {
        kdb_init_cpu = -1;       /* leaving kdb */
        goto out;                /* rc properly set to 0 or 1 */
    }
    if (reason != KDB_REASON_PAUSE_IPI) {
        kdb_cpu_cmd[ccpu] = KDB_CPU_MAIN_KDB;
    } else
        kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;

    if (kdb_cpu_cmd[ccpu] == KDB_CPU_MAIN_KDB && !ss_mode)
        kdb_begin_session(); 

    kdb_main_entry_misc(reason, regs, ccpu, ss_mode, enabled);
    /* note, one or more cpu switches may occur in between */
    while (1) {
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_PAUSE)
            kdb_hold_this_cpu(ccpu, regs);
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_MAIN_KDB)
            kdb_do_cmds(regs);

        if (kdb_cpu_cmd[ccpu] == KDB_CPU_GO) {
            if (ccpu != kdb_init_cpu) {
                kdb_cpu_cmd[kdb_init_cpu] = KDB_CPU_GO;
                kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
                continue;               /* for the pause guy */
            }
            if (!cpumask_empty(&kdb_cpu_traps)) {
                /* execute current instruction without 0xcc */
                kdb_dbg_prnt_ctrps("nempty:", ccpu);
                if (guest_mode(regs) && !is_pv_vcpu(current))
                    current->arch.hvm_vcpu.single_step = 1;
                else
                    regs->eflags |= X86_EFLAGS_TF;  
                kdb_cpu_cmd[ccpu] = KDB_CPU_INSTALL_BP;
                goto out;
            }
        }
        if (kdb_cpu_cmd[ccpu] != KDB_CPU_PAUSE  && 
            kdb_cpu_cmd[ccpu] != KDB_CPU_MAIN_KDB)
                break;
    }
    if (kdb_cpu_cmd[ccpu] == KDB_CPU_GO) {
        ASSERT(cpumask_empty(&kdb_cpu_traps));
        if (kdb_swbp_exists()) {
            if (reason == KDB_REASON_BPEXCP) {
                /* do delayed install */
                if (guest_mode(regs) && !is_pv_vcpu(current))
                    current->arch.hvm_vcpu.single_step = 1;
                else
                    regs->eflags |= X86_EFLAGS_TF;  
                kdb_cpu_cmd[ccpu] = KDB_CPU_INSTALL_BP;
                goto out;
            } 
        }
        kdb_end_session(ccpu, regs);
        kdb_init_cpu = -1;
    }
out:
    if (kdb_cpu_cmd[ccpu] == KDB_CPU_QUIT) {
        KDBGP("ccpu:%d _quit IP: %lx\n", ccpu, regs->KDBIP);
        if (! kdb_session_begun)
            kdb_install_watchpoints();
        kdb_time_resume(0);
        kdb_cpu_cmd[ccpu] = KDB_CPU_INVAL;
    }

    /* for ss and delayed install, TF is set. not much in EXT INT handlers*/
    if (kdb_cpu_cmd[ccpu] == KDB_CPU_NI)
        kdb_time_resume(1);
    if (enabled)
        local_irq_enable();

    KDBGP("kdbmain:X:ccpu:%d rc:%d cmd:%d eflg:0x%lx initc:%d sesn:%d " 
          "cs:%x irqs:%d ", ccpu, rc, kdb_cpu_cmd[ccpu], regs->eflags, 
          kdb_init_cpu, kdb_session_begun, regs->cs, local_irq_is_enabled());
    kdb_dbg_prnt_ctrps("", -1);
    return (rc ? 1 : 0);
}

/* 
 * kdb entry function when coming in via a keyboard
 * RETURNS: 0 : kdb was called for event it was not responsible
 *          1 : event owned and handled by kdb 
 */
int
kdb_keyboard(struct cpu_user_regs *regs)
{
    return kdbmain(KDB_REASON_KEYBOARD, regs);
}

#if 0
/*
 * this function called when kdb session active and user presses ctrl\ again.
 * the assumption is that the user typed ni/ss cmd, and it never got back into
 * kdb, or the user is impatient. Either case, we just fake it that the SS did
 * finish. Since, all other kdb cpus must be holding disabled, the interrupt
 * would be on the CPU that did the ss/ni cmd
 */
void
kdb_ssni_reenter(struct cpu_user_regs *regs)
{
    int ccpu = smp_processor_id();
    int ccmd = kdb_cpu_cmd[ccpu];

    if(ccmd == KDB_CPU_SS || ccmd == KDB_CPU_INSTALL_BP)
        kdbmain(KDB_REASON_DBEXCP, regs); 
    else 
        kdbmain(KDB_REASON_KEYBOARD, regs);
}
#endif

/* 
 * All traps are routed thru here. We care about BP (#3) trap (INT 3) and
 * the DB trap(#1) only. 
 * returns: 0 kdb has nothing do with this trap
 *          1 kdb handled this trap 
 */
int
kdb_handle_trap_entry(int vector, const struct cpu_user_regs *regs1)
{
    int rc = 0;
    int ccpu = smp_processor_id();
    struct cpu_user_regs *regs = (struct cpu_user_regs *)regs1;

    if (vector == TRAP_int3) {
        rc = kdbmain(KDB_REASON_BPEXCP, regs);

    } else if (vector == TRAP_debug) {
        KDBGP("ccpu:%d trapdbg reas:%d\n", ccpu, kdb_trap_immed_reason);

        if (kdb_trap_immed_reason == KDB_TRAP_FATAL) { 
            KDBGP("kdbtrp:fatal ccpu:%d vec:%d\n", ccpu, vector);
            rc = kdbmain_fatal(regs, vector);
            BUG();                             /* no return */

        } else if (kdb_trap_immed_reason == KDB_TRAP_KDBSTACK) {
            kdb_trap_immed_reason = 0;         /* show kdb stack */
            show_registers(regs);
            show_stack(regs);
            regs->eflags &= ~X86_EFLAGS_TF;
            rc = 1;

        } else if (kdb_trap_immed_reason == KDB_TRAP_NONFATAL) {
            kdb_trap_immed_reason = 0;
            rc = kdb_keyboard(regs);
        } else {                         /* ss/ni/delayed install... */
            if (guest_mode(regs) && !is_pv_vcpu(current))
                current->arch.hvm_vcpu.single_step = 0;
            rc = kdbmain(KDB_REASON_DBEXCP, regs); 
        }

    } else if (vector == TRAP_nmi) {                   /* external nmi */
        /* when nmi is pressed, it could go to one or more or all cpus
         * depending on the hardware. Also, for now assume it's fatal */
        KDBGP("kdbtrp:ccpu:%d vec:%d\n", ccpu, vector);
        rc = kdbmain_fatal(regs, TRAP_nmi);
    } 
    return rc;
}

int
kdb_trap_fatal(int vector, struct cpu_user_regs *regs)
{
    kdbmain_fatal(regs, vector);
    return 0;
}

/* From smp_send_nmi_allbutself() in crash.c which is static */
void
kdb_nmi_pause_cpus(cpumask_t cpumask)
{
    int ccpu = smp_processor_id();
    mdelay(200);
    cpumask_complement(&cpumask, &cpumask);              /* flip bit map */
    cpumask_and(&cpumask, &cpumask, &cpu_online_map);    /* remove extra bits */
    cpumask_clear_cpu(ccpu, &cpumask);/* absolutely make sure we're not on it */

    KDBGP("ccpu:%d nmi pause. mask:0x%lx\n", ccpu, cpumask.bits[0]);
    if ( !cpumask_empty(&cpumask) )
#if XEN_SUBVERSION > 4 || XEN_VERSION == 4              /* xen 3.5.x or above */
        send_IPI_mask(&cpumask, APIC_DM_NMI);
#else
        send_IPI_mask(cpumask, APIC_DM_NMI);
#endif
    mdelay(200);
    KDBGP("ccpu:%d nmi pause done...\n", ccpu);
}

/* 
 * Separate function from kdbmain to keep both within sanity levels.
 */
DEFINE_SPINLOCK(kdb_fatal_lk);
static int
kdbmain_fatal(struct cpu_user_regs *regs, int vector)
{
    int ccpu = smp_processor_id();

    console_start_sync();

    KDBGP("mainf:ccpu:%d vec:%d irq:%d\n", ccpu, vector,local_irq_is_enabled());
    cpumask_set_cpu(ccpu, &kdb_fatal_cpumask);        /* uses LOCK_PREFIX */

    if (spin_trylock(&kdb_fatal_lk)) {

        kdbp("*** kdb (Fatal Error on cpu:%d vec:%d %s):\n", ccpu,
             vector, kdb_gettrapname(vector));
        kdb_cpu_cmd[ccpu] = KDB_CPU_MAIN_KDB;
        kdb_display_pc(regs);

        watchdog_disable();     /* important */
        kdb_sys_crash = 1;
        kdb_session_begun = 0;  /* incase session already active */
        local_irq_enable();
        kdb_nmi_pause_cpus(kdb_fatal_cpumask);

        kdb_clear_prev_cmd();   /* buffered CRs will repeat prev cmd */
        kdb_session_begun = 1;  /* for kdb_hold_this_cpu() */
        local_irq_disable();
    } else {
        kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
    }
    while (1) {
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_PAUSE)
            kdb_hold_this_cpu(ccpu, regs);
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_MAIN_KDB)
            kdb_do_cmds(regs);
#if 0
        /* dump is the only way to exit in crashed state */
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_DUMP)
            kdb_do_dump(regs);
#endif
    }
    return 0;
}

/* Mostly called in fatal cases. earlykdb calls non-fatal.
 * kdb_trap_immed_reason is global, so allow only one cpu at a time. Also,
 * multiple cpu may be crashing at the same time. We enable because if there
 * is a bad hang, at least ctrl-\ will break into kdb. Also, we don't call
 * call kdb_keyboard directly becaue we don't have the register context.
 */
DEFINE_SPINLOCK(kdb_immed_lk);
void
kdb_trap_immed(int reason)            /* fatal, non-fatal, kdb stack etc... */
{
    int ccpu = smp_processor_id();
    int disabled = !local_irq_is_enabled();

    KDBGP("trapimm:ccpu:%d reas:%d\n", ccpu, reason);
    local_irq_enable();
    spin_lock(&kdb_immed_lk);
    kdb_trap_immed_reason = reason;
    barrier();
    __asm__ __volatile__ ( "int $1" );
    kdb_trap_immed_reason = 0;

    spin_unlock(&kdb_immed_lk);
    if (disabled)
        local_irq_disable();
}

/* called very early during init, even before all CPUs are brought online */
void 
kdb_init(void)
{
        kdb_init_cmdtab();      /* Initialize Command Table */
}

static const char *
kdb_gettrapname(int trapno)
{
    char *ret;
    switch (trapno) {
        case  0:  ret = "Divide Error"; break;
        case  2:  ret = "NMI Interrupt"; break;
        case  3:  ret = "Int 3 Trap"; break;
        case  4:  ret = "Overflow Error"; break;
        case  6:  ret = "Invalid Opcode"; break;
        case  8:  ret = "Double Fault"; break;
        case 10:  ret = "Invalid TSS"; break;
        case 11:  ret = "Segment Not Present"; break;
        case 12:  ret = "Stack-Segment Fault"; break;
        case 13:  ret = "General Protection"; break;
        case 14:  ret = "Page Fault"; break;
        case 17:  ret = "Alignment Check"; break;
        default: ret = " ????? ";
    }
    return ret;
}


/* ====================== Generic perf/stat subsystem ====================== */
uint kdb_stat0[NR_CPUS];
uint kdb_stat1[NR_CPUS];
uint kdb_stat2[NR_CPUS];
uint kdb_stat3[NR_CPUS];

void kdb_update_stats(uint d0, uint d1, ulong l0, ulong l1)
{
    int ccpu = smp_processor_id();

    switch (d0)
    {
        case 129:
            kdb_stat0[ccpu]++;
            break;

        case 130:
            kdb_stat1[ccpu]++;
            break;

        case 131:
            kdb_stat2[ccpu]++;
            break;

        case 132:
            kdb_stat3[ccpu]++;
            break;
    }
}

void kdb_clear_stats(void)
{
    memset(kdb_stat0, 0, sizeof(kdb_stat0));
    memset(kdb_stat1, 0, sizeof(kdb_stat1));
    memset(kdb_stat2, 0, sizeof(kdb_stat2));
    memset(kdb_stat3, 0, sizeof(kdb_stat3));
}

/* ====================== Generic tracing subsystem ======================== */

#define KDBTRCMAX 1       /* set this to max number of recs to trace. each rec 
                           * is 32 bytes */
volatile int kdb_trcon=1; /* turn tracing ON: set here or via the trcon cmd */

typedef struct {
    union {
        struct { uint d0; uint cpu_trcid; } s0;
        uint64_t l0;
    }u;
    uint64_t l1, l2, l3; 
} trc_rec_t;

static volatile unsigned int trcidx;    /* points to where new entry will go */
static trc_rec_t trca[KDBTRCMAX];       /* trace array */

/* atomically: add i to *p, return prev value of *p (ie, val before add) */
int kdb_fetch_and_add(int i, uint *p)
{
    asm volatile("lock xaddl %0, %1;" : "=r"(i) : "m"(*p), "0"(i));
    return i;
}

/* zero out the entire buffer */
void kdb_trczero(void)
{
    for (trcidx = KDBTRCMAX-1; trcidx; trcidx--) {
        memset(&trca[trcidx], 0, sizeof(trc_rec_t));
    }
    memset(&trca[trcidx], 0, sizeof(trc_rec_t));
    kdbp("kdb trace buffer has been zeroed\n");
}

/* add trace entry: eg.: kdbtrc(0xe0f099, intdata, vcpu, domain, 0)
 *    where:  0xe0f099 : 24bits max trcid, lower 8 bits are set to cpuid */
void
kdbtrc(uint trcid, uint int_d0, uint64_t d1_64, uint64_t d2_64, uint64_t d3_64)
{
    uint idx;

    if (!kdb_trcon)
        return;

    idx = kdb_fetch_and_add(1, (uint*)&trcidx);
    idx = idx % KDBTRCMAX;

#if 0
    trca[idx].u.s0.cpu_trcid = (smp_processor_id()<<24) | trcid;
#endif
    trca[idx].u.s0.cpu_trcid = (trcid<<8) | smp_processor_id();
    trca[idx].u.s0.d0 = int_d0;
    trca[idx].l1 = d1_64;
    trca[idx].l2 = d2_64;
    trca[idx].l3 = d3_64;
}

/* give hints so user can print trc buffer via the dd command. last has the
 * most recent entry */
void kdb_trcp(void)
{
    int i = trcidx % KDBTRCMAX;

    i = (i==0) ? KDBTRCMAX-1 : i-1;
    kdbp("trcbuf:    [0]: %016lx [MAX-1]: %016lx\n", &trca[0],
         &trca[KDBTRCMAX-1]);
    kdbp(" [most recent]: %016lx   trcidx: 0x%x\n", &trca[i], trcidx);
}


void noinline mukchk(unsigned long ul)
{
}
