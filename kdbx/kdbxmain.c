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

#include "include/kdbxinc.h"

extern int rcu_cpu_stall_suppress;

// extern struct tty_driver *kdbx_tty_driver;


static int kdbmain(kdb_reason_t, struct pt_regs *);

/* ======================== GLOBAL VARIABLES =============================== */
/* All global variables used by KDB must be defined here only. Module specific
 * static variables must be declared in respective modules.
 */
kdbtab_t *kdb_cmd_tbl;
char kdb_prompt[32];

volatile kdb_cpu_cmd_t kdb_cpu_cmd[NR_CPUS];
// cpumask_t kdbx_cpu_traps;          /* bit per cpu to tell which cpus hit int3 */

#if 0
#ifndef NDEBUG
    #error KDB is not supported on debug xen. Turn debug off
#endif
#endif

volatile int kdb_init_cpu = -1;           /* initial kdb cpu */
volatile int kdbx_session_begun = 0;      /* active kdb session? */
volatile int kdb_enabled = 1;             /* kdb enabled currently? */
volatile int kdb_sys_crash = 0;           /* are we in crashed state? */
volatile int kdbdbg = 0;                  /* to debug kdb itself */

static int kdb_pause_nmi_inprog = 0;
static volatile int kdb_trap_immed_reason = 0;   /* reason for immed trap */
static ulong vmx_handle_external_intr_s, vmx_handle_external_intr_e;

/* return index of first bit set in val. if val is 0, retval is undefined */
static inline unsigned int kdb_firstbit(unsigned long val)
{
    __asm__ ( "bsf %1,%0" : "=r" (val) : "r" (val), "0" (BITS_PER_LONG) );
    return (unsigned int)val;
}

static void kdb_dbg_prnt_ctrps(char *label, int ccpu)
{
#if 0
    if (label || *label)
        KDBGP1("%s ", label);
    if (ccpu != -1)
        KDBGP1("ccpu:%d ", ccpu);
    KDBGP1("cputrps: %lx\n", kdbx_cpu_traps.bits[0]);
#endif
}

/* 
 * Hold this cpu. Don't disable until all CPUs in kdb to avoid IPI deadlock 
 */
static void kdb_hold_this_cpu(int ccpu, struct pt_regs *regs)
{
    clear_tsk_need_resched(current);
    do {
        KDBGP("[%d]in hold. cmd:%x\n", ccpu, kdb_cpu_cmd[ccpu]);
        for(; kdb_cpu_cmd[ccpu] == KDB_CPU_PAUSE; cpu_relax());
#if 0
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_DISABLE) {
            local_irq_disable();
            kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
#endif
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_DO_VMEXIT) {
            kdbx_curr_cpu_flush_vmcs();
            kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_SHOWPC) {
            kdbxp("[%d]", ccpu);
            kdb_display_pc(regs);
            kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
    } while (kdb_cpu_cmd[ccpu] == KDB_CPU_PAUSE);     /* No goto, eh! */
    KDBGP("[%d]Unhold: cmd:%d\n", ccpu, kdb_cpu_cmd[ccpu]);
}

static void kdb_watchdog_disable(void)
{
    extern int watchdog_user_enabled;
    watchdog_user_enabled = 0;
}

/* pause other cpus via an IPI. Note, disabled CPUs can't receive IPIs until
 * enabled */
static void kdb_smp_pause_cpus(void)
{
    int cpu, wait_count = 0;
    int ccpu = smp_processor_id();      /* current cpu */
    struct cpumask cpumask; 
    
    cpumask_copy(&cpumask, cpu_online_mask);
    cpumask_clear_cpu(ccpu, &cpumask);

    kdb_pause_nmi_inprog = 1;

    /* SMP IPI: smp_call_function(). smp_call_function_interrupt is called.
     * sends NMI_LOCAL=0 type nmi. kdbx_nmi_handler() will be called */
    apic->send_IPI_allbutself(NMI_VECTOR);

    mdelay(100);                     /* wait a bit for other CPUs to stop */
    while(wait_count++ < 3000) {
        int bummer = 0;

        for_each_cpu(cpu, &cpumask)
            if (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE) {
                bummer = 1;
            }
        if (!bummer)
            break;
        mdelay(1);  /* shorter wait, longer count */
    };
    for_each_cpu(cpu, &cpumask) {        /* now check who is with us */
        if (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE)
            kdbxp("[%d]Bummer cpu %d not paused, cmd:%d\n", ccpu, cpu,
                  kdb_cpu_cmd[cpu]); 
        else {
#if 0
            kdb_cpu_cmd[cpu] = KDB_CPU_DISABLE;  /* tell it to disable ints */
            while (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE);
#endif
        }
    }
    kdb_pause_nmi_inprog = 0;
}

/* 
 * Do once per kdb session:  A kdb session lasts from 
 *    keybord/HWBP/SWBP till KDB_CPU_INSTALL_BP is done. Within a session,
 *    user may do several cpu switches, single step, next instr,  etc..
 *
 * DO: 1. pause other cpus if they are not already. they would already be 
 *        if we are in single step mode
 *     2. kdb_watchdog_disable() 
 *     3. uninstall all sw breakpoints so that user doesn't see them
 */
static void kdb_begin_session(void)
{
    if ( !kdbx_session_begun ) {
        kdbx_session_begun = 1;
        kdb_smp_pause_cpus();
        // local_irq_disable();
        kdb_watchdog_disable();
        kdb_uninstall_all_swbp();
        rcu_cpu_stall_suppress = 1;
        clear_tsk_need_resched(current);
    }
}

static void kdb_smp_unpause_cpus(int ccpu)
{
    int cpu;

    int wait_count = 0;
    cpumask_t cpumask = *cpu_online_mask;

    cpumask_clear_cpu(smp_processor_id(), &cpumask);

    KDBGP("[%d]kdb_smp_unpause_other_cpus()\n", ccpu);
    for_each_cpu(cpu, &cpumask)
        kdb_cpu_cmd[cpu] = KDB_CPU_QUIT;

    while(wait_count++ < 2000) {
        int bummer = 0;
        for_each_cpu(cpu, &cpumask) {
            if (kdb_cpu_cmd[cpu] != KDB_CPU_INVAL)
                bummer = 1;
            if (!bummer)
                break;
            mdelay(1);  /* short wait, longer count */
        }
    };
    /* now make sure they are all in there */
    for_each_cpu(cpu, &cpumask)
        if (kdb_cpu_cmd[cpu] != KDB_CPU_INVAL)
            kdbxp("[%d]KDB: cpu %d still paused (cmd==%d).\n",
                 ccpu, cpu, kdb_cpu_cmd[cpu]);
}

/*
 * End of KDB session. 
 *   This is called at the very end. In case of multiple cpus hitting BPs
 *   and sitting on a trap handlers, the last cpu to exit will call this.
 *   - isnstall all sw breakpoints, and purge deleted ones from table.
 *   - clear TF here also in case go is entered on a different cpu after switch
 */
static void kdb_end_session(int ccpu, struct pt_regs *regs)
{
    // ASSERT(cpumask_empty(&kdbx_cpu_traps));
    ASSERT(kdbx_session_begun);
    kdb_install_all_swbp();
    kdb_flush_swbp_table();
    kdb_install_watchpoints();

    regs->flags &= ~X86_EFLAGS_TF;
    kdb_cpu_cmd[ccpu] = KDB_CPU_INVAL;
    // kdb_time_resume(1);
    kdbx_session_begun = 0;    /* before unpause for kdb_install_watchpoints */
    rcu_cpu_stall_reset();
    kdb_smp_unpause_cpus(ccpu);
    /* kdb_watchdog_enable(); */
    KDBGP("[%d]kdb_end_session\n", ccpu);
}

/* 
 * check if we entered kdb because of DB trap. If yes, then check if
 * we caused it or someone else.
 * RETURNS: 0 : not one of ours. hypervisor must handle it. 
 *          1 : #DB for delayed sw bp install. 
 *          2 : this cpu must stay in kdb.
 */
static noinline int
kdb_check_dbtrap(kdb_reason_t *reasp, int ss_mode, struct pt_regs *regs) 
{
    int rc = 2;
    int ccpu = smp_processor_id();

    /* DB excp caused by hw breakpoint or the TF flag. The TF flag is set
     * by us for ss mode or to install breakpoints. In ss mode, none of the
     * breakpoints are installed. Check to make sure we intended BP INSTALL
     * so we don't do it on a spurious DB trap.
     * check for kdbx_cpu_traps here also, because each cpu sitting on a trap
     * must execute the instruction without the BP before passing control
     * to next cpu in kdbx_cpu_traps.
     */
    if (*reasp == KDB_REASON_DBEXCP && !ss_mode) {
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_INSTALL_BP) {

#if 0
            if (!cpumask_empty(&kdbx_cpu_traps)) {
                int a_trap_cpu = cpumask_first(&kdbx_cpu_traps);

                KDBGP("ccpu:%d trapcpu:%d\n", ccpu, a_trap_cpu);
                kdb_cpu_cmd[a_trap_cpu] = KDB_CPU_QUIT;
                *reasp = KDB_REASON_PAUSE_IPI;
                regs->flags &= ~X86_EFLAGS_TF;  /* hvm: exit handler ss = 0 */
                kdb_init_cpu = -1;
            } else {
#endif

                kdb_end_session(ccpu, regs);
                rc = 1;
            // }
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
kdb_main_entry_misc(kdb_reason_t reason, struct pt_regs *regs, 
                    int ccpu, int ss_mode, int enabled)
{
    if (reason == KDB_REASON_KEYBOARD)
        kdbxp("\nEnter kdb (cpu:%d reason:%d pid=%d eflg:0x%lx irqs:%d)\n",
             ccpu, reason, current->pid, regs->flags, enabled);
    else if (ss_mode)
        KDBGP1("KDBG: KDB single step mode. ccpu:%d\n", ccpu);

    if (reason == KDB_REASON_BPEXCP && !ss_mode) 
        kdbxp("Breakpoint on cpu %d at 0x%lx\n", ccpu, regs->KDBIP);

    /* display the current PC and instruction at it */
    if (reason != KDB_REASON_PAUSE_IPI)
        kdb_display_pc(regs);
}

static void kdb_set_single_step(struct pt_regs *regs)
{
    if ( kdb_guest_mode(regs) ) {
        struct kvm_vcpu *vp = kdb_pid_to_vcpu(current->pid, 0);

        vp->guest_debug |= KVM_GUESTDBG_SINGLESTEP;
    } else
        regs->flags |= X86_EFLAGS_TF;  
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
static int kdbmain(kdb_reason_t reason, struct pt_regs *regs)
{
    int ccpu = smp_processor_id();                /* current cpu */
    int rc = 1, cmd = kdb_cpu_cmd[ccpu];
    int ss_mode = (cmd == KDB_CPU_SS || cmd == KDB_CPU_NI);
    int enabled = irqs_enabled();

    KDBGP("[%d]kdbmain: rsn:%d eflgs:0x%lx cmd:%d initc:%d irqs:%d "
          "regs:%lx IP:%lx cpid:%d\n", ccpu, reason, regs->flags, cmd, 
          kdb_init_cpu, enabled, regs, regs->KDBIP, current->pid);
    kdb_dbg_prnt_ctrps("", -1);

    if (!ss_mode && ccpu != kdb_init_cpu && reason != KDB_REASON_PAUSE_IPI) {
        int sz = sizeof(kdb_init_cpu);

        while (__cmpxchg(&kdb_init_cpu, -1, ccpu, sz) != -1)
            for(; kdb_init_cpu != -1; cpu_relax());
    }

#if 0
Dont enable. what if the pause NMI came to the CPU in disabled code?
maybe change from NMI back to just IPIs?

    /* The CPU disables INTs on external INT, but the state of interrupted
     * thread is saved in eflags.IF on the stack. When we resume, that
     * state will be restored via the eflag. so we can just enable here. Since,
     * we come here even for non-kdb exceptions, must check for kdb session */
    if ( kdbx_session_begun )
        local_irq_enable();             /* kdb always runs enabled now */
#endif

    if (reason == KDB_REASON_BPEXCP) {             /* INT 3 */
        // cpumask_clear_cpu(ccpu, &kdbx_cpu_traps);  /* remove ourself */

        rc = kdb_check_sw_bkpts(regs);
        if (rc == 0) {               /* not one of ours. leave kdb */
            kdb_init_cpu = -1;
            goto out;
        } else if (rc == 1) {        /* one of ours but deleted */
                kdb_end_session(ccpu,regs);     
                kdb_init_cpu = -1;
                goto out;
#if 0
            if (cpumask_empty(&kdbx_cpu_traps)) {
                kdb_end_session(ccpu,regs);     
                kdb_init_cpu = -1;
                goto out;
            } else {                 
                /* release another trap cpu, and put ourself in a pause mode */
                int a_trap_cpu = cpumask_first(&kdbx_cpu_traps);

                KDBGP("ccpu:%d cmd:%d rsn:%d atrpcpu:%d initcpu:%d\n", ccpu, 
                      kdb_cpu_cmd[ccpu], reason, a_trap_cpu, kdb_init_cpu);
                kdb_cpu_cmd[a_trap_cpu] = KDB_CPU_QUIT;
                reason = KDB_REASON_PAUSE_IPI;
                kdb_init_cpu = -1;
            }
#endif
        } else if (rc == 2) {        /* one of ours but condition not met */
                kdb_begin_session();
                kdb_set_single_step(regs);
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
            kdb_do_cmds(regs);          /* will set kdb_cpu_cmd[ccpu] */

        if (kdb_cpu_cmd[ccpu] == KDB_CPU_GO) {
            if (ccpu != kdb_init_cpu) {
                kdb_cpu_cmd[kdb_init_cpu] = KDB_CPU_GO;
                kdb_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
                continue;               /* for the pause guy */
            }
#if 0
            if (!cpumask_empty(&kdbx_cpu_traps)) {
                /* execute current instruction without 0xcc */
                kdb_dbg_prnt_ctrps("nempty:", ccpu);
                kdb_set_single_step(regs);
                kdb_cpu_cmd[ccpu] = KDB_CPU_INSTALL_BP;
                goto out;
            }
#endif
        }
        if (kdb_cpu_cmd[ccpu] != KDB_CPU_PAUSE  && 
            kdb_cpu_cmd[ccpu] != KDB_CPU_MAIN_KDB)
                break;
    }
    if (kdb_cpu_cmd[ccpu] == KDB_CPU_GO) {
        // ASSERT(cpumask_empty(&kdbx_cpu_traps));
        if (kdb_swbp_exists()) {
            if (reason == KDB_REASON_BPEXCP) {
                /* do delayed install */
                kdb_set_single_step(regs);
                kdb_cpu_cmd[ccpu] = KDB_CPU_INSTALL_BP;
                goto out;
            } 
        }
        kdb_end_session(ccpu, regs);
        kdb_init_cpu = -1;
    }
out:
    if (kdb_cpu_cmd[ccpu] == KDB_CPU_QUIT) {
        KDBGP1("ccpu:%d _quit IP: %lx\n", ccpu, regs->KDBIP);
        if (! kdbx_session_begun )
            kdb_install_watchpoints();
        // kdb_time_resume(0);
        kdb_cpu_cmd[ccpu] = KDB_CPU_INVAL;
    }

#if 0
    if (kdb_cpu_cmd[ccpu] == KDB_CPU_NI)
        kdb_time_resume(1);

    if (enabled)
        local_irq_enable();
#endif

    KDBGP("[%d]kdbmain:X: rc:%d cmd:%d regs:%p eflg:0x%lx initc:%d sesn:%d " 
          "cs:%x irqs:%d\n", ccpu, rc, kdb_cpu_cmd[ccpu], regs, regs->flags, 
          kdb_init_cpu, kdbx_session_begun, regs->cs, irqs_enabled());
    // kdb_dbg_prnt_ctrps("", -1);

    return (rc ? 1 : 0);
}

/* 
 * kdbx entry function when coming in via a keyboard
 * keyboard: vmxexit --> handle_external_interrupt --> do_IRQ --> kdbx_keyboard
 * RETURNS: 0 : kdbx was called for event it was not responsible
 *          1 : event owned and handled by kdb 
 */
int kdbx_keyboard(struct pt_regs *regs)
{
    int rc;
    struct pt_regs gregs;
    struct kvm_vcpu *vp = NULL;

kdbdbg = 1;

    if ( regs->ip >= vmx_handle_external_intr_s && 
         regs->ip <= vmx_handle_external_intr_e &&
         (vp = kdb_pid_to_vcpu(current->pid, 0)) )
    {
kdbxp(">>>>>>> IP in vmx_handle_external_intr_s\n");
        kdb_vcpu_to_ptregs(vp, &gregs);
        gregs.flags |= ( (ulong)1 << 63 );     /* NOT from VMCS */
        regs = &gregs;
    }

    rc = kdbmain(KDB_REASON_KEYBOARD, regs);

    if ( vp ) {
        gregs.flags &= ~( (ulong)1 << 63 );   /* ignored anyways by vmcs */
        kdb_ptregs_to_vcpu(vp, regs);
    }

    return rc;

#if 0
    int host_rsp = kdb_on_host_rsp(regs);
    int enabled = irqs_enabled();

    if ( ! kdbx_tty_driver )
        kdbx_init_console();

    if ( ! kdbx_tty_driver ) {
        printk(KERN_EMERG "kdbx: console io is not inialized\n");
        return 0;
    }
    local_irq_disable();
    if ( host_rsp )     /* stack is vmx host_rsp, so must be from guest */
        regs->flags |= ( (ulong)1 << 63 );    /* checked in kdb_guest_mode() */

    rc = kdbmain(KDB_REASON_KEYBOARD, regs);
    if ( host_rsp )
        regs->flags &= ~( (ulong)1 << 63 );
    if ( enabled )
        local_irq_enable();
#endif
}

#if 0
/*
 * this function called when kdb session active and user presses ctrl\ again.
 * the assumption is that the user typed ni/ss cmd, and it never got back into
 * kdb, or the user is impatient. Either case, we just fake it that the SS did
 * finish. Since, all other kdb cpus must be holding disabled, the interrupt
 * would be on the CPU that did the ss/ni cmd
 */
void kdb_ssni_reenter(struct pt_regs *regs)
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
 * Traps, EXCEPT NMI, are routed thru here. We care about BP (#3) (INT 3),
 * and the DB trap(#1) only. 
 * returns: 0 kdb has nothing do with this trap
 *          1 kdb handled this trap 
 */
int kdbx_handle_trap_entry(int vector, const struct pt_regs *regs1)
{
    int rc = 0;
    int ccpu = smp_processor_id();
    struct pt_regs *regs = (struct pt_regs *)regs1;

    KDBGP("[%d]handle_trap: vector:%d IP:%lx\n", ccpu, vector, regs->ip);

    if (vector == X86_TRAP_BP) {
        rc = kdbmain(KDB_REASON_BPEXCP, regs);

    } else if (vector == X86_TRAP_DB) {
        KDBGP("[%d]trapdbg reas:%d\n", ccpu, kdb_trap_immed_reason);

        if (kdb_trap_immed_reason == KDBX_TRAP_FATAL) { 
            KDBGP("kdbtrp:fatal ccpu:%d vec:%d\n", ccpu, vector);
            kdbxmain_fatal(regs, vector);
            BUG();                             /* no return */

        } else if (kdb_trap_immed_reason == KDBX_TRAP_KDBSTACK) {
            kdb_trap_immed_reason = 0;    /* show kdb stack */
            kdb_print_regs(regs);
            kdb_show_stack(regs, 0);      /* always host */
            regs->flags &= ~X86_EFLAGS_TF;
            rc = 1;

        } else if (kdb_trap_immed_reason == KDBX_TRAP_NONFATAL) {
            kdb_trap_immed_reason = 0;
            rc = kdbmain(KDB_REASON_KEYBOARD, regs);
        } else {                         /* ss/ni/delayed install... */
            rc = kdbmain(KDB_REASON_DBEXCP, regs); 
        }
    } 

    return rc;
}

/* 
 * In case of external NMI, the BMC could send it to one or multiple CPUs.
 * NON guest CPUs, guest mode CPUs thru kdbx_handle_guest_trap().
 * External NMI:
 *   - Single CPU: NMI to single cpu, go to kdbmain, which will then NMI pause
 *                 all other CPUs.
 *   - Multiple: All CPUs will come here, one will get the lock, and 
 *               go thru kdbmain
 * Internal: kdb_init_cpu sending NMIs to rest of the CPUs to pause.
 */
void kdbx_do_nmi(struct pt_regs *regs, int err_code)
{
    int ccpu = smp_processor_id();

    KDBGP("[%d]kdbx_do_nmi pausenmi:%d\n", ccpu, kdb_pause_nmi_inprog);
    if ( kdb_pause_nmi_inprog ) {

        /* it's a pause NMI from kdb main cpu.
         * Pause this cpu while one CPU does main kdb processing. If that CPU 
         * does a "cpu switch" to this cpu, this cpu will become the main kdb 
         * cpu. If the user next does single step of some sort, this 
         * function will be exited, and this cpu will come back into kdb 
         * via kdbx_handle_trap_entry function. 
         */

        kdbmain(KDB_REASON_PAUSE_IPI, regs);
        KDBGP("[%d]kdbx_do_nmi return.\n", ccpu);

        return;
    }

    /* External NMIs are fatal */
    kdbxmain_fatal(regs, X86_TRAP_NMI);

    return;
}

/* 
 * guest DB, NMI, and BP thru here
 * keyboard: vmxexit --> handle_external_interrupt --> do_IRQ --> kdbx_keyboard
 */
int kdbx_handle_guest_trap(int vector, struct kvm_vcpu *vp)
{
    int rc;
    struct pt_regs regs;

    kdb_vcpu_to_ptregs(vp, &regs);
    regs.flags |= ( (ulong)1 << 63 );  /* NOT from VMCS. kdb_guest_mode() */

    if ( vector == X86_TRAP_NMI ) {
        kdbx_do_nmi(&regs, -1);
        rc = 1;
    } else {
        rc = kdbx_handle_trap_entry(vector, &regs);
    }
    regs.flags &= ~( (ulong)1 << 63 );  /* ignored. NOT copied to VMCS */
    kdb_ptregs_to_vcpu(vp, &regs);

    return rc;
}

/* called from kdbxmain_fatal and kdb_cmds-> send nmi to cpu/s */
void kdb_nmi_pause_cpus(struct cpumask cpumask)
{
    int ccpu = smp_processor_id();

    cpumask_complement(&cpumask, &cpumask);              /* flip bit map */
    cpumask_and(&cpumask, &cpumask, cpu_online_mask);    /* remove extra bits */
    cpumask_clear_cpu(ccpu, &cpumask);/* absolutely make sure we're not on it */

    KDBGP("[%d] nmi pause. mask:0x%lx\n", ccpu, cpumask.bits[0]);
    if ( !cpumask_empty(&cpumask) )
        apic->send_IPI_mask_allbutself(&cpumask, NMI_VECTOR);
}

DEFINE_SPINLOCK(kdb_nmi_lk);
static struct cpumask kdb_fatal_cpumask;         /* which cpus in fatal path */
void kdbxmain_fatal(struct pt_regs *regs, int vector)
{
    int ccpu = smp_processor_id();

    cpumask_set_cpu(ccpu, &kdb_fatal_cpumask);   /* uses LOCK_PREFIX */

    if (spin_trylock(&kdb_nmi_lk)) {

        kdbxp("*** kdb (Fatal Error on cpu:%d vec/err_code:%d):\n",ccpu,vector);
        kdb_cpu_cmd[ccpu] = KDB_CPU_MAIN_KDB;
        kdb_display_pc(regs);

        kdb_watchdog_disable();         /* important */
        kdb_sys_crash = 1;
        kdbx_session_begun = 0;         /* incase session already active */
        local_irq_enable();

        mdelay(150);
        kdb_nmi_pause_cpus(kdb_fatal_cpumask);

        kdb_clear_prev_cmd();   /* buffered CRs will repeat prev cmd */
        kdbx_session_begun = 1; /* for kdb_hold_this_cpu() */
        local_irq_disable();
    } else {
        kdbmain(KDB_REASON_PAUSE_IPI, regs);
    }

    while (1) {
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_PAUSE)
            kdb_hold_this_cpu(ccpu, regs);
        if (kdb_cpu_cmd[ccpu] == KDB_CPU_MAIN_KDB)
            kdb_do_cmds(regs);
    }
}

/* Mostly called in fatal cases. earlykdbx calls non-fatal.
 * kdb_trap_immed_reason is global, so allow only one cpu at a time. Also,
 * multiple cpu may be crashing at the same time. We enable because if there
 * is a bad hang, at least ctrl-\ will break into kdb. Also, we don't call
 * call kdbx_keyboard directly becaue we don't have the register context.
 */
DEFINE_SPINLOCK(kdb_immed_lk);
void kdbx_trap_immed(int reason)        /* fatal, non-fatal, kdb stack etc... */
{
    int ccpu = smp_processor_id();
    int disabled = irqs_disabled();

    KDBGP("[%d]trapimm: reas:%d\n", ccpu, reason);
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

#if 0
/* cmd: NMI_LOCAL, NMI_UNKNOWN, ... */
/* When externally generated NMI, some BIOSs will send NMI to all CPUs. So,
 * get a lock.
 */
static int kdbx_nmi_handler(struct pt_regs *regs, int error_code)
{
    static int in_nmi[NR_CPUS];
    int ccpu = smp_processor_id();

    kdbxp("[%d]:kdbx_do_nmi() err:%d\n", smp_processor_id(), error_code);

    if ( in_nmi[ccpu] ) {
        kdbxp("[%d] spurious nmi:%d\n", ccpu, cmd);
        return NMI_HANDLED;
    } else 
        in_nmi[ccpu] = 1;

    kdbxp("[%d] nmi handler: nmi:%d\n", ccpu, cmd);
    if ( kdb_init_cpu != -1 ) {
        /* 
         * Internal nmi from fellow kdb cpu.
         *
         * Pause this cpu while one CPU does main kdb processing. If that CPU 
         * does a "cpu switch" to this cpu, this cpu will become the main kdb 
         * cpu. If the user next does single step of some sort, this 
         * function will be exited, and this cpu will come back into kdb 
         * via kdbx_handle_trap_entry function. 
         */
        kdbmain(KDB_REASON_PAUSE_IPI, regs);
        while (kdb_init_cpu != -1) {
            /* wait so that immediate spurious NMIs don't hang kdb */
            mdelay(50);
        }
    } else {
        if ( cmd == NMI_UNKNOWN )
            /* external nmi, lets call it fatal */
            kdbxmain_fatal(regs, X86_TRAP_NMI);
        else
            kdbxp("[%d]kdbx: ignoring the nmi:%d\n", ccpu, cmd);
    }
    in_nmi[ccpu] = 0;
    return NMI_HANDLED;
}
#endif

static void kdbx_init_vmx_extint_info(void)
{
    ulong sz, offs;
    char buf[KSYM_NAME_LEN+1];
    ulong addr = kallsyms_lookup_name("vmx_handle_external_intr");

    if ( addr == 0 ) {
        /* pr_notice : so it's in the dmesg */
        pr_notice(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>KDBX kdbx\n");
        pr_notice(">> kdbx: vmx_handle_external_intr not found\n");
        return;
    }

    if ( kallsyms_lookup(addr, &sz, &offs, NULL, buf) == NULL || sz == 0 ) {
        pr_notice(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>KDBX kdbx\n");
        pr_notice(">> kdbx: vmx_handle_external_intr addr not found\n");
        return;
    }
    vmx_handle_external_intr_s = addr;
    vmx_handle_external_intr_e = addr + sz;
}

/* called very early during init */
void __init kdbx_init(char *boot_command_line)
{
    kdb_init_cmdtab();      /* Initialize Command Table */
    kdbx_init_console(boot_command_line);
    kdbx_init_vmx_extint_info();

#if 0
    int rc;

    rc = register_nmi_handler(NMI_LOCAL, kdbx_nmi_handler, 0, "kdbx");
    if (rc)
        kdbxp("KDBX: Failed to register for NMI_LOCAL\n");

    rc = register_nmi_handler(NMI_UNKNOWN, kdbx_nmi_handler, 0, "kdbx");
    if ( rc )
        kdbxp("KDBX: Failed to register for NMI_UNKNOWN\n");

    rc = register_nmi_handler(NMI_SERR, kdbx_nmi_handler, 0, "kdbx");
    if ( rc )
        kdbxp("KDBX: Failed to register for NMI_SERR\n");

    rc = register_nmi_handler(NMI_IO_CHECK, kdbx_nmi_handler, 0, "kdbx");
    if ( rc )
        kdbxp("KDBX: Failed to register for NMI_IO_CHECK\n");
#endif
}

#if 0
static const char *kdb_gettrapname(int trapno)
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
#endif


/* ====================== Generic tracing subsystem ======================== */
/* TIMESTAMP/DELAY : use sched_clock() for timestamps tracing */

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
static int kdb_fetch_and_add(int i, uint *p)
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
    kdbxp("kdb trace buffer has been zeroed\n");
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
    kdbxp("trcbuf:    [0]: %016lx [MAX-1]: %016lx\n", &trca[0],
         &trca[KDBTRCMAX-1]);
    kdbxp(" [most recent]: %016lx   trcidx: 0x%x\n", &trca[i], trcidx);
}


void noinline mukchk(unsigned long ul)
{
}

