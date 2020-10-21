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


static int kdbxmain(kdbx_reason_t, struct pt_regs *);

/* ======================== GLOBAL VARIABLES =============================== */

volatile kdbx_cpu_cmd_t kdbx_cpu_cmd[NR_CPUS];

#if 0
#ifndef NDEBUG
    #error KDB is not supported on debug xen. Turn debug off
#endif
#endif

volatile int kdb_init_cpu = -1;           /* initial kdb cpu */
volatile int kdbx_session_begun = 0;      /* active kdb session? */
volatile int kdbx_sys_crash = 0;          /* are we in crashed state? */
volatile int kdbdbg = 0;                  /* to debug kdb itself */

static volatile int kdb_trap_immed_reason = 0;   /* reason for immed trap */
static ulong vmx_handle_external_intr_s, vmx_handle_external_intr_e;

/* return index of first bit set in val. if val is 0, retval is undefined */
static inline unsigned int kdb_firstbit(unsigned long val)
{
    __asm__ ( "bsf %1,%0" : "=r" (val) : "r" (val), "0" (BITS_PER_LONG) );
    return (unsigned int)val;
}

static int kdbx_running_in_vm(void)
{
    uint eax, ebx, ecx, edx;

    cpuid(0x40000000, &eax, &ebx, &ecx, &edx);
    if ( ebx == 0x4b4d564b && ecx == 0x564b4d56 ) {  /* KVMKVM */
        /* TBD: add check for xen */
        return 1;
    }
    return 0;
}

static void kdbx_cpu_relax(void)
{
    if ( !kdbx_running_in_vm() )
        cpu_relax();
}

/* 
 * Hold this cpu. Don't disable until all CPUs in kdb to avoid IPI deadlock 
 */
static void kdb_hold_this_cpu(struct pt_regs *regs)
{
    int ccpu = smp_processor_id();      /* current cpu */

    clear_tsk_need_resched(current);
    KDBGP1("[%d]in hold. cmd:%x\n", ccpu, kdbx_cpu_cmd[ccpu]);
    do {
        for(; kdbx_cpu_cmd[ccpu] == KDB_CPU_PAUSE; kdbx_cpu_relax());

        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_DISABLE) {
            local_irq_disable();
            kdbx_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_DO_VMEXIT) {
            kdbx_curr_cpu_flush_vmcs();
            kdbx_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_SHOWPC) {
            kdbxp("[%d]", ccpu);
            kdbx_display_pc(regs);
            kdbx_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
        }
    } while (kdbx_cpu_cmd[ccpu] == KDB_CPU_PAUSE);     /* No goto, eh! */
    KDBGP("[%d]Unhold: cmd:%d\n", ccpu, kdbx_cpu_cmd[ccpu]);
}

static void kdbx_pause_this_cpu(void *info)
{
    kdbxmain(KDB_REASON_PAUSE_IPI, get_irq_regs());
}

/* pause other cpus via an IPI. Note, disabled CPUs can't receive IPIs until
 * enabled */
static void kdb_smp_pause_cpus(void)
{
    int cpu, wait_count = 0;
    int ccpu = smp_processor_id();      /* current cpu */
    struct cpumask cpumask; 
    int running_in_vm = kdbx_running_in_vm();
    int loop_max = running_in_vm ? 3000 : 2000;
    
    cpumask_copy(&cpumask, cpu_online_mask);
    cpumask_clear_cpu(ccpu, &cpumask);
    smp_call_function_many(&cpumask, kdbx_pause_this_cpu, NULL, 0);

    mdelay(100);                     /* wait a bit for other CPUs to stop */
    while(wait_count++ < loop_max) {
        int bummer = 0;

        for_each_cpu(cpu, &cpumask)
            if (kdbx_cpu_cmd[cpu] != KDB_CPU_PAUSE) {
                bummer = 1;
            }
        if (!bummer)
            break;
        mdelay(1);  /* shorter wait, longer count */
    };
    for_each_cpu(cpu, &cpumask) {        /* now check who is with us */
        if (kdbx_cpu_cmd[cpu] != KDB_CPU_PAUSE)
            kdbxp("[%d]Bummer cpu %d not paused, cmd:%d\n", ccpu, cpu,
                  kdbx_cpu_cmd[cpu]); 
        else {
            if ( running_in_vm ) {
                kdbx_cpu_cmd[cpu] = KDB_CPU_DISABLE;/* tell it to disable ints*/
                while (kdbx_cpu_cmd[cpu] != KDB_CPU_PAUSE);
                KDBGP("[%d]: cpu:%d disabled\n", ccpu, cpu);
            }
        }
    }
    if ( running_in_vm ) {
        KDBGP("[%d]: disabled\n", ccpu);
        local_irq_disable();
    }
}

static void kdbx_watchdog_disable(void)
{
    extern int watchdog_user_enabled;
    watchdog_user_enabled = 0;
}

/* 
 * Do once per kdb session:  A kdb session lasts from 
 *    keybord/HWBP/SWBP till KDB_CPU_INSTALL_BP is done. Within a session,
 *    user may do several cpu switches, single step, next instr,  etc..
 *
 * DO: 1. pause other cpus if they are not already. they would already be 
 *        if we are in single step mode
 *     2. kdbx_watchdog_disable() 
 *     3. uninstall all sw breakpoints so that user doesn't see them
 */
static void kdb_begin_session(void)
{
    if ( !kdbx_session_begun ) {
        kdbx_session_begun = 1;
        kdb_smp_pause_cpus();
        kdbx_watchdog_disable();
        kdbx_uninstall_all_swbp();
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
        kdbx_cpu_cmd[cpu] = KDB_CPU_QUIT;

    mdelay(3);
    while(wait_count++ < 3000) {
        int bummer = 0;

        for_each_cpu(cpu, &cpumask) {
            if (kdbx_cpu_cmd[cpu] != KDB_CPU_INVAL)
                bummer = 1;
        }
        if (!bummer)
            break;
        mdelay(1);  /* short wait, longer count */
    };
    /* now make sure they are all in there */
    for_each_cpu(cpu, &cpumask)
        if (kdbx_cpu_cmd[cpu] != KDB_CPU_INVAL)
            kdbxp("[%d]KDB: cpu %d still paused (cmd==%d).\n",
                 ccpu, cpu, kdbx_cpu_cmd[cpu]);
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
    ASSERT(kdbx_session_begun);
    kdbx_install_all_swbp();
    kdbx_flush_swbp_table();
    kdbx_install_watchpoints();

    regs->flags &= ~X86_EFLAGS_TF;
    kdbx_cpu_cmd[ccpu] = KDB_CPU_INVAL;
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
kdb_check_dbtrap(kdbx_reason_t *reasp, int ss_mode, struct pt_regs *regs) 
{
    int rc = 2;
    int ccpu = smp_processor_id();

    /* DB excp caused by hw breakpoint or the TF flag. The TF flag is set
     * by us for ss mode or to install breakpoints. In ss mode, none of the
     * breakpoints are installed. Check to make sure we intended BP INSTALL
     * so we don't do it on a spurious DB trap.
     */
    if (*reasp == KDB_REASON_DBEXCP && !ss_mode) {
        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_INSTALL_BP) {
                kdb_end_session(ccpu, regs);
                rc = 1;
            // }
        } else if (! kdbx_check_watchpoints(regs)) {
            rc = 0;                        /* hyp must handle it */
        }
    }
    return rc;
}

/* 
 * Misc processing on kdb entry like displaying PC, adjust IP for sw bp.... 
 */
static void
kdb_main_entry_misc(kdbx_reason_t reason, struct pt_regs *regs, 
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
        kdbx_display_pc(regs);
}

static void kdb_set_single_step(struct pt_regs *regs)
{
    if ( kdbx_guest_mode(regs) ) {
        struct kvm_vcpu *vp = kdbx_pid_to_vcpu(current->pid, 0);

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
static int kdbxmain(kdbx_reason_t reason, struct pt_regs *regs)
{
    int ccpu = smp_processor_id();                /* current cpu */
    int rc = 1, cmd = kdbx_cpu_cmd[ccpu];
    int ss_mode = (cmd == KDB_CPU_SS || cmd == KDB_CPU_NI);
    // int delayed_install = (kdbx_cpu_cmd[ccpu] == KDB_CPU_INSTALL_BP);
    int enabled = irqs_enabled();

    KDBGP("[%d]kdbxmain: rsn:%d eflgs:0x%lx cmd:%d initc:%d irqs:%d "
          "regs:%lx IP:%lx cpid:%d\n", ccpu, reason, regs->flags, cmd, 
          kdb_init_cpu, enabled, regs, regs->KDBIP, current->pid);

    local_irq_enable();              /* so we can receive IPI */

    if (!ss_mode && ccpu != kdb_init_cpu && reason != KDB_REASON_PAUSE_IPI) {
        int sz = sizeof(kdb_init_cpu);

        while (__cmpxchg(&kdb_init_cpu, -1, ccpu, sz) != -1)
            for(; kdb_init_cpu != -1; cpu_relax());
    }

    if (reason == KDB_REASON_BPEXCP) {             /* INT 3 */
        rc = kdbx_check_sw_bkpts(regs);
        if (rc == 0) {               /* not one of ours. leave kdb */
            kdb_init_cpu = -1;
            goto out;
        } else if (rc == 1) {        /* one of ours but deleted */
                kdb_end_session(ccpu,regs);     
                kdb_init_cpu = -1;
                goto out;
        } else if (rc == 2) {        /* one of ours but condition not met */
                kdb_begin_session();
                kdb_set_single_step(regs);
                kdbx_cpu_cmd[ccpu] = KDB_CPU_INSTALL_BP;
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
        kdbx_cpu_cmd[ccpu] = KDB_CPU_MAIN_KDB;
    } else
        kdbx_cpu_cmd[ccpu] = KDB_CPU_PAUSE;

    if (kdbx_cpu_cmd[ccpu] == KDB_CPU_MAIN_KDB && !ss_mode)
        kdb_begin_session(); 

    /* Upon getting an interrupt, the cpu turns INTs off */
    if (enabled)
        kdbxp("[%d]kdbx: warn: entering main enabled\n", ccpu);

    kdb_main_entry_misc(reason, regs, ccpu, ss_mode, enabled);

    /* note, one or more cpu switches may occur in between */
    while (1) {
        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_PAUSE)
            kdb_hold_this_cpu(regs);
        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_MAIN_KDB)
            kdbx_do_cmds(regs);          /* will set kdbx_cpu_cmd[ccpu] */

        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_GO) {
            if (ccpu != kdb_init_cpu) {
                kdbx_cpu_cmd[kdb_init_cpu] = KDB_CPU_GO;
                kdbx_cpu_cmd[ccpu] = KDB_CPU_PAUSE;
                continue;               /* for the pause guy */
            }
        }
        if (kdbx_cpu_cmd[ccpu] != KDB_CPU_PAUSE  && 
            kdbx_cpu_cmd[ccpu] != KDB_CPU_MAIN_KDB)
                break;
    }
    if (kdbx_cpu_cmd[ccpu] == KDB_CPU_GO) {
        if (kdbx_swbp_exists()) {
            if (reason == KDB_REASON_BPEXCP) {
                /* do delayed install */
                kdb_set_single_step(regs);
                kdbx_cpu_cmd[ccpu] = KDB_CPU_INSTALL_BP;
                goto out;
            } 
        }
        kdb_end_session(ccpu, regs);
        kdb_init_cpu = -1;
    }
out:
    if (kdbx_cpu_cmd[ccpu] == KDB_CPU_QUIT) {
        KDBGP1("ccpu:%d _quit IP: %lx\n", ccpu, regs->KDBIP);
        if (! kdbx_session_begun )
            kdbx_install_watchpoints();
        // kdb_time_resume(0);
        kdbx_cpu_cmd[ccpu] = KDB_CPU_INVAL;
    }

#if 0
    if (kdbx_cpu_cmd[ccpu] == KDB_CPU_NI)
        kdb_time_resume(1);

    if (enabled)
        local_irq_enable();
#endif

    local_irq_disable();
    KDBGP("[%d]kdbxmain:X: rc:%d cmd:%d regs:%p eflg:0x%lx initc:%d sesn:%d " 
          "cs:%x irqs:%d\n", ccpu, rc, kdbx_cpu_cmd[ccpu], regs, regs->flags, 
          kdb_init_cpu, kdbx_session_begun, regs->cs, irqs_enabled());

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

    if ( vmx_handle_external_intr_e == 0 )
        kdbxp("kdbx WARN: vmx_handle_external_intr_e is null\n");

    if ( regs->ip >= vmx_handle_external_intr_s && 
         regs->ip <= vmx_handle_external_intr_e &&
         (vp = kdbx_pid_to_vcpu(current->pid, 0)) )
    {
        kdbx_vcpu_to_ptregs(vp, &gregs);
        gregs.flags |= ( (ulong)1 << 63 );     /* NOT from VMCS */
        regs = &gregs;
    }

    rc = kdbxmain(KDB_REASON_KEYBOARD, regs);

    if ( vp ) {
        gregs.flags &= ~( (ulong)1 << 63 );   /* ignored anyways by vmcs */
        kdbx_ptregs_to_vcpu(vp, regs);
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

    rc = kdbxmain(KDB_REASON_KEYBOARD, regs);
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
    int ccmd = kdbx_cpu_cmd[ccpu];

    if(ccmd == KDB_CPU_SS || ccmd == KDB_CPU_INSTALL_BP)
        kdbxmain(KDB_REASON_DBEXCP, regs); 
    else 
        kdbxmain(KDB_REASON_KEYBOARD, regs);
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
        rc = kdbxmain(KDB_REASON_BPEXCP, regs);

    } else if (vector == X86_TRAP_DB) {
        KDBGP("[%d]trapdbg reas:%d\n", ccpu, kdb_trap_immed_reason);

        if (kdb_trap_immed_reason == KDBX_TRAP_FATAL) { 
            KDBGP("kdbtrp:fatal ccpu:%d vec:%d\n", ccpu, vector);
            kdbxmain_fatal(regs, vector);
            BUG();                             /* no return */

        } else if (kdb_trap_immed_reason == KDBX_TRAP_KDBSTACK) {
            kdb_trap_immed_reason = 0;    /* show kdb stack */
            kdbx_print_regs(regs);
            kdbx_show_stack(regs, 0);      /* always host */
            regs->flags &= ~X86_EFLAGS_TF;
            rc = 1;

        } else if (kdb_trap_immed_reason == KDBX_TRAP_NONFATAL) {
            kdb_trap_immed_reason = 0;
            rc = kdbxmain(KDB_REASON_KEYBOARD, regs);
        } else {                         /* ss/ni/delayed install... */
            rc = kdbxmain(KDB_REASON_DBEXCP, regs); 
        }
    } 

    return rc;
}

/* 
 * In case of external NMI, the BMC could send it to one or multiple CPUs.
 * NON guest CPUs, guest mode CPUs thru kdbx_handle_guest_trap().
 * External NMI:
 *   - Single CPU: NMI to single cpu, go to kdbxmain, which will then NMI pause
 *                 all other CPUs.
 *   - Multiple: All CPUs will come here, one will get the lock, and 
 *               go thru kdbxmain
 * Internal: kdb_init_cpu sending NMIs to rest of the CPUs to pause.
 */
void kdbx_do_nmi(struct pt_regs *regs, int err_code)
{
#if 0
    int ccpu = smp_processor_id();

    if ( kdb_pause_nmi_inprog ) {

        /* it's a pause NMI from kdb main cpu.
         * Pause this cpu while one CPU does main kdb processing. If that CPU 
         * does a "cpu switch" to this cpu, this cpu will become the main kdb 
         * cpu. If the user next does single step of some sort, this 
         * function will be exited, and this cpu will come back into kdb 
         * via kdbx_handle_trap_entry function. 
         */

        kdbxmain(KDB_REASON_PAUSE_IPI, regs);
        KDBGP("[%d]kdbx_do_nmi return.\n", ccpu);

        return;
    }
#endif
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

    kdbx_vcpu_to_ptregs(vp, &regs);
    regs.flags |= ( (ulong)1 << 63 );  /* NOT from VMCS. kdb_guest_mode() */

    if ( vector == X86_TRAP_NMI ) {
        kdbx_do_nmi(&regs, -1);
        rc = 1;
    } else {
        rc = kdbx_handle_trap_entry(vector, &regs);
    }
    regs.flags &= ~( (ulong)1 << 63 );  /* ignored. NOT copied to VMCS */
    kdbx_ptregs_to_vcpu(vp, &regs);

    return rc;
}

/* called from kdbxmain_fatal and kdb_cmds-> send nmi to cpu/s */
void kdbx_nmi_pause_cpus(struct cpumask cpumask)
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

        kdbxp("** kdbx (Fatal Error on cpu:%d vec+err_code:%x):\n",ccpu,vector);
        kdbx_cpu_cmd[ccpu] = KDB_CPU_MAIN_KDB;
        kdbx_display_pc(regs);

        kdbx_watchdog_disable();         /* important */
        kdbx_sys_crash = 1;
        kdbx_session_begun = 0;         /* incase session already active */
        local_irq_enable();

        mdelay(150);
        kdbx_nmi_pause_cpus(kdb_fatal_cpumask);

        kdbx_clear_prev_cmd();   /* buffered CRs will repeat prev cmd */
        kdbx_session_begun = 1;  /* for kdb_hold_this_cpu() */
        local_irq_disable();
    } else {
        kdbxmain(KDB_REASON_PAUSE_IPI, regs);
    }

    while (1) {
        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_PAUSE)
            kdb_hold_this_cpu(regs);
        if (kdbx_cpu_cmd[ccpu] == KDB_CPU_MAIN_KDB)
            kdbx_do_cmds(regs);
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
    if ( reason != KDBX_TRAP_KDBSTACK )
        local_irq_enable();
    spin_lock(&kdb_immed_lk);
    kdb_trap_immed_reason = reason;
    barrier();
    __asm__ __volatile__ ( "int $1" );
    kdb_trap_immed_reason = 0;

    spin_unlock(&kdb_immed_lk);
    if (reason != KDBX_TRAP_KDBSTACK && disabled)
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
        kdbxmain(KDB_REASON_PAUSE_IPI, regs);
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
    kdbx_init_cmdtab();      /* Initialize Command Table */
    kdbx_init_io(boot_command_line);
    kdbx_init_vmx_extint_info();
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
volatile int kdbx_trcon=0; /* turn tracing ON: set here or via the trcon cmd */

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
void kdbx_trczero(void)
{
    for (trcidx = KDBTRCMAX-1; trcidx; trcidx--) {
        memset(&trca[trcidx], 0, sizeof(trc_rec_t));
    }
    memset(&trca[trcidx], 0, sizeof(trc_rec_t));
    kdbxp("kdb trace buffer has been zeroed\n");
}

/* add trace entry: eg.: kdbtrc(0xe0f099, intdata, vcpu, domain, 0)
 *    where:  0xe0f099 : 24bits max trcid, upper 8 bits are set to cpuid */
void kdbxtrc(uint trcid, uint int_d0, uint64_t d1_64, uint64_t d2_64, 
             uint64_t d3_64)
{
    uint idx;

    if (!kdbx_trcon)
        return;

    idx = kdb_fetch_and_add(1, (uint*)&trcidx);
    idx = idx % KDBTRCMAX;

    trca[idx].u.s0.cpu_trcid = (smp_processor_id()<<24) | trcid;
    trca[idx].u.s0.d0 = int_d0;
    trca[idx].l1 = d1_64;
    trca[idx].l2 = d2_64;
    trca[idx].l3 = d3_64;
}

/* give hints so user can print trc buffer via the dd command. last has the
 * most recent entry */
void kdbx_trcp(void)
{
    int i = trcidx % KDBTRCMAX;

    i = (i==0) ? KDBTRCMAX-1 : i-1;
    kdbxp("trcbuf:    [0]: %016lx [MAX-1]: %016lx\n", &trca[0],
         &trca[KDBTRCMAX-1]);
    kdbxp(" [most recent]: %016lx   trcidx: 0x%x\n", &trca[i], trcidx);
}


/* execute any generic action in kernel from sysrq: 
 *       echo c > /proc/sysrq-trigger
 */
void kdbx_handle_sysrq_c(int key)
{
}

void noinline mukchk(unsigned long ul)
{
}

/* =========== */

/* see sched_clock() */
static inline ulong kdb_nsecs(void)
{
        unsigned long long nsec;

        nsec =  (unsigned long long)(jiffies - INITIAL_JIFFIES)
                                        * (NSEC_PER_SEC / HZ);
        return (nsec);
}

ulong kdbx_usecs(void)
{
    return kdb_nsecs() >> 10;
}

int mukadd(int i, uint *p)
{
    if (p == NULL)
        return 0;

    asm volatile("lock xaddl %0, %1;" : "=r"(i) : "m"(*p), "0"(i));
    return i;
}
EXPORT_SYMBOL(mukadd);

ulong mukaddl(int i, ulong *p)
{
    ulong l = (ulong)i;

    asm volatile("lock xaddq %0, %1;" : "=r"(l) : "m"(*p), "0"(l));
    return l;
}
EXPORT_SYMBOL(mukaddl);
