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

#include "include/kdbxinc.h"

#if defined(__x86_64__)
    #define KDBF64 "%lx"
    #define KDBFL "%016lx"         /* print long all digits */
#else
    #define KDBF64 "%llx"
    #define KDBFL "%08lx"
#endif

#define KDB_PGLLE(t) ((t).tail)    /* page list last element ^%$#@ */

#define KDB_CMD_HISTORY_COUNT   32
#define CMD_BUFLEN              200     /* kdb_printf: max printline == 256 */

#define KDBMAXSBP 1024                  /* max number of software breakpoints */
#define KDB_MAXARGC 16                  /* max args in a kdb command */
#define KDB_MAXBTP  8                   /* max display args in btp */

static struct kdbxtab *kdb_cmd_tbl;
static char kdb_prompt[32];

static char sbuf1[KSYM_NAME_LEN+64], sbuf2[KSYM_NAME_LEN+64],
            sbuf3[KSYM_NAME_LEN+64], sbuf4[KSYM_NAME_LEN+64],
            sbuf5[KSYM_NAME_LEN+64], sbuf6[KSYM_NAME_LEN+64],
            sbuf7[KSYM_NAME_LEN+64], sbuf8[KSYM_NAME_LEN+64];
char *sbuf_ptrs[] = {sbuf1, sbuf2, sbuf3, sbuf4, sbuf5, sbuf6, sbuf7, sbuf8};

/* condition is: 'r6 == 0x123f' or '0xffffffff82800000 != deadbeef'  */
struct kdb_bpcond {
    kdbbyt_t bp_cond_status;       /* 0 == off, 1 == register, 2 == memory */
    kdbbyt_t bp_cond_type;         /* 0 == bad, 1 == equal, 2 == not equal */
    ulong    bp_cond_lhs;          /* lhs of condition: reg offset or mem loc */
    ulong    bp_cond_rhs;          /* right hand side of condition */
};

/* software breakpoint structure */
struct kdb_sbrkpt {
    kdbva_t  bp_addr;              /* address the bp is set at */
    pid_t    bp_pid;               /* which pid bp belongs to. 0 == all host */
    kdbbyt_t bp_originst;          /* save orig instr/s here */
    kdbbyt_t bp_deleted;           /* delete pending on this bp */
    kdbbyt_t bp_ni;                /* set for KDB_CPU_NI */
    kdbbyt_t bp_just_added;        /* added in the current kdb session */
    kdbbyt_t bp_type;              /* 0 = normal, 1 == cond,  2 == btp */
    union {
        struct kdb_bpcond bp_cond;
        ulong *bp_btp;
    } u;
};

/* don't use kmalloc in kdb which hijacks all cpus */
static ulong kdb_btp_argsa[KDBMAXSBP][KDB_MAXBTP];
static ulong *kdb_btp_ap[KDBMAXSBP];

static struct kdb_reg_nmofs {
    char *reg_nm;
    int reg_offs;
} kdb_reg_nm_offs[] =  {
       { "ax", offsetof(struct pt_regs, ax) },
       { "bx", offsetof(struct pt_regs, bx) },
       { "cx", offsetof(struct pt_regs, cx) },
       { "dx", offsetof(struct pt_regs, dx) },
       { "si", offsetof(struct pt_regs, si) },
       { "di", offsetof(struct pt_regs, di) },
       { "bp", offsetof(struct pt_regs, bp) },
       { "sp", offsetof(struct pt_regs, sp) },
       { "r8",  offsetof(struct pt_regs, r8) },
       { "r9",  offsetof(struct pt_regs, r9) },
       { "r10", offsetof(struct pt_regs, r10) },
       { "r11", offsetof(struct pt_regs, r11) },
       { "r12", offsetof(struct pt_regs, r12) },
       { "r13", offsetof(struct pt_regs, r13) },
       { "r14", offsetof(struct pt_regs, r14) },
       { "r15", offsetof(struct pt_regs, r15) },
       { "flags", offsetof(struct pt_regs, flags) } };

static const int KDBBPSZ=1;                   /* size of KDB_BPINST is 1 byte*/
static kdbbyt_t kdb_bpinst = 0xcc;            /* breakpoint instr: INT3 */
static struct kdb_sbrkpt kdb_sbpa[KDBMAXSBP]; /* soft brkpt array/table */
static struct kdbxtab *tbp;

#define DDBUFSZ 4096
static kdbbyt_t kdb_membuf[DDBUFSZ];    /* can't allocate on stack of this sz */

static int kdb_set_bp(pid_t, kdbva_t, int, ulong *, char*, char*, char*);


/* ===================== cmdline functions  ================================ */
/* lp points to a string of only alpha numeric chars terminated by '\n'.
 * Parse the string into argv pointers, and RETURN argc
 * Eg:  if lp --> "dr  sp\n" :  argv[0]=="dr\0"  argv[1]=="sp\0"  argc==2
 */
static int kdb_parse_cmdline(char *lp, const char **argv)
{
    int i=0;

    for (; *lp == ' '; lp++);      /* note: isspace() skips '\n' also */
    while ( *lp != '\n' ) {
        if (i == KDB_MAXARGC) {
            kdbxp("kdb: max args exceeded\n");
            break;
        }
        argv[i++] = lp;
        for (; *lp != ' ' && *lp != '\n'; lp++);
        if (*lp != '\n')
            *lp++ = '\0';
        for (; *lp == ' '; lp++);
    }
    *lp = '\0';
    return i;
}

void kdbx_clear_prev_cmd()             /* so previous command is not repeated */
{
    tbp = NULL;
}

struct kdbx_excp_resume_state {
    ulong resume_rip;   /* ip to resume execution at */
    ulong resume_rsp;   /* stack pointer to restore */
    ulong resume_r12;
    ulong resume_r13;
    ulong resume_r14;
    ulong resume_r15;
    ulong resume_rbx;
    ulong resume_rbp;
};
struct kdbx_excp_resume_state kdbx_excp_sav, *kdbx_excp_ptr = &kdbx_excp_sav;
int kdbx_in_fixup;

/* returns: 0 if fixup done. 1 implies exception in fixup path */
int kdbx_excp_fixup(struct pt_regs *regs)
{
    struct kdbx_excp_resume_state *excp = &kdbx_excp_sav;
    int ccpu = smp_processor_id();

    if ( kdbx_in_fixup )
        return 1;     /* nested exception, ignore */

    kdbx_in_fixup = 1;
    regs->ip = excp->resume_rip;
    regs->sp = excp->resume_rsp;
    regs->r12 = excp->resume_r12;
    regs->r13 = excp->resume_r13;
    regs->r14 = excp->resume_r14;
    regs->r15 = excp->resume_r15;
    regs->bx = excp->resume_rbx;
    regs->bp = excp->resume_rbp;

    regs->ax = KDB_CPU_MAIN_KDB;
    kdbxp("[%d]kdbx fixup done: ip: %lx sp: %lx\n", ccpu, regs->ip, regs->sp);
    memset(excp, 0, sizeof(struct kdbx_excp_resume_state));

    return 0;
}

void kdbx_do_cmds(struct pt_regs *regs)
{
    char *cmdlinep;
    const char *argv[KDB_MAXARGC];
    int argc = 0, curcpu = smp_processor_id();
    kdbx_cpu_cmd_t result = KDB_CPU_MAIN_KDB;

    snprintf(kdb_prompt, sizeof(kdb_prompt), "[%d]kdbx> ", curcpu);

    while (result == KDB_CPU_MAIN_KDB) {
        cmdlinep = kdbx_get_input(kdb_prompt);
        if (*cmdlinep == '\n') {
            if (tbp==NULL || tbp->kdb_cmd_func==NULL)
                continue;
            else
                argc = -1;    /* repeat prev command */
        } else {
            argc = kdb_parse_cmdline(cmdlinep, argv);
            for(tbp=kdb_cmd_tbl; tbp->kdb_cmd_func; tbp++)  {
                if (strcmp(argv[0], tbp->kdb_cmd_name)==0) 
                    break;
            }
        }
        if (tbp->kdb_cmd_func) {
            if (kdbx_sys_crash && !tbp->kdb_cmd_crash_avail) {
                kdbxp("cmd not available in fatal/crashed state....\n");
                continue;
            }
            if ( argc > 1 && *argv[1] == '?') {
                tbp->kdb_cmd_usgf();
                continue;
            }
            result = kdbx_call_cmd_func(argc, argv, regs, tbp->kdb_cmd_func);
            // result = (*tbp->kdb_cmd_func)(argc, argv, regs);
            if (tbp->kdb_cmd_repeat == KDBX_REPEAT_NONE)
                tbp = NULL;
        } else
            kdbxp("kdb: Unknown cmd: %s\n", cmdlinep);
    }
    kdbx_cpu_cmd[curcpu] = result;
}

/* ===================== Util functions  ==================================== */

static void kdbx_prnt_cpumask(struct cpumask *mask, char *nl)
{
    int cpu;

    for_each_cpu(cpu, mask) {
        kdbxp(" %d", cpu);
    }
    kdbxp("%s", nl);
}

static int kdbx_text_addr(ulong addr, pid_t guest_pid)
{
    if ( guest_pid )
        return kdbx_is_addr_guest_text(addr, guest_pid);

    return __kernel_text_address(addr);
}

#define KDBX_SYM_IDX_MAX 16
static int kdbx_sym_idx;
struct kdbx_sym_info {
    char sym_name_found[KSYM_NAME_LEN+1]; /* not sure if includes null char */
    ulong sym_addr;
};
static struct kdbx_sym_info kdbx_sym_infoa[KDBX_SYM_IDX_MAX];

/* ret num of chars before "." or \0 if no dot found */
static int kdbx_sym_find_dot(char *name)
{
    int len;

    /* some symbols begin with dot, like .slowpath, .LC17 etc.. allow that */
    for (len=0; *name; name++, len++)
        if (*name == '.' && len)
            break;

    return len;
}

/* Note: static symbols will occur multiple times, eg. x2apic_send_IPI. 
 *  Also: part of a function could be inlined too.. eg:
 *    console_trylock and console_trylock.part.17
 *
 * Other examples:
 *    mutex_lock.isra.19
 *    cpumask_weight.constprop.26
 */
static int kdbx_sym_callback(void *data, const char *name,
                             struct module *mod, unsigned long addr)
{
    void *dst;
    char *symname = data;  /* name for which we are looking for address */
    int dotlen = kdbx_sym_find_dot((char *)name);

    if (dotlen == 0 || strncmp(symname, name, dotlen) != 0) 
        return 0;

    /* we were looking for console_trylock.part.17, but found console_trylock */
    if ( strlen(name) < strlen(symname) )
        return 0;

    if ( kdbx_sym_idx >= KDBX_SYM_IDX_MAX ) {
        kdbxp("kdbx_sym_idx overflow : %d\n", kdbx_sym_idx);
        return -1;   /* iteration will stop */
    }

    /* save full name including .constprop/.isra etc.. */
    dst = kdbx_sym_infoa[kdbx_sym_idx].sym_name_found;
    memcpy(dst, name, strlen(name)+1);
    kdbx_sym_infoa[kdbx_sym_idx++].sym_addr = addr;

    return 0;
}

/* Given a symbol, find it's address. NOT smp safe, call one cpu at a time */
kdbva_t kdb_sym2addr(char *p, pid_t gpid)
{
    kdbva_t addr = 0;

    KDBGP1("sym2addr: p:%s gpid:%d\n", p, gpid);
    if ( gpid )
        addr = kdbx_guest_sym2addr((char *)p, gpid);
    else {
        kdbx_sym_idx = 0;
        memset(kdbx_sym_infoa, 0, sizeof(kdbx_sym_infoa));
        kallsyms_on_each_symbol(kdbx_sym_callback, p);

        if ( kdbx_sym_idx == 0 )
            addr = 0;
        else if ( kdbx_sym_idx == 1 )
            addr = kdbx_sym_infoa[0].sym_addr;
        else {
            int i;

            addr = 0;
            kdbxp("  Multiple addresses for symbol: %s\n", p);
            for (i=0; i< kdbx_sym_idx; i++) {
                kdbxp("  %lx %s\n", kdbx_sym_infoa[i].sym_addr,
                      kdbx_sym_infoa[i].sym_name_found);
                
                /* if there is exact match, use that. print above warning too?*/
                if (strcmp(p, kdbx_sym_infoa[i].sym_name_found) == 0)
                    addr = kdbx_sym_infoa[i].sym_addr;
            }
            kdbxp("\n");
        }
    }
    KDBGP1("sym2addr: exit: addr returned:0x%lx\n", addr);
    return addr;
}

/* also called from drivers/block/virtio_blk.c etc.. */
/* can be specified as function argument upto 8 times:
 *    kdbxp("%s %s %s\n", kdbx_hostsym(a1), kdbx_hostsym(a2)... */
char *kdbx_hostsym(void *addr)
{
    static int ctr;

    return kdbx_addr2sym(0, (kdbva_t)addr, sbuf_ptrs[ctr++%8], 0);
}

/*
 * convert ascii to int decimal (base 10). 
 * Return: 0 : failed to convert, otherwise 1 
 */
static int kdb_str2decil(const char *strp, ulong *ulp)
{
    char *endp;

    KDBGP2("str2decil: str:%s\n", strp);
    if ( !isdigit(*strp) )
        return 0;
    *ulp = simple_strtoul(strp, &endp, 10);
    if (endp != strp+strlen(strp))
        return 0;
    KDBGP2("str2decil: val:$%d\n", *ulp);

    return 1;
}

/* Return: 0 : failed to convert, otherwise 1  */
static int kdb_str2deci(const char *strp, int *intp)
{
    int rc;
    ulong ulval;

    if ( (rc = kdb_str2decil(strp, &ulval)) )
        *intp = (int)ulval;

    return rc; 
}

/*
 * convert ascii to long. NOTE: base is 16
 * Return: 0 : failed to convert, otherwise 1 
 */
static int kdb_str2ulong(const char *strp, ulong *longp)
{
    ulong val;
    char *endp;

    KDBGP2("str2long: str:%s\n", strp);
    if (!isxdigit(*strp))
        return 0;
    val = (long)simple_strtoul(strp, &endp, 16);   /* handles leading 0x */
    if (endp != strp+strlen(strp))
        return 0;
    if (longp)
        *longp = val;
    KDBGP2("str2long: val:0x%lx\n", val);
    return 1;
}

/*
 * convert a symbol or ascii address to hex address
 * Return: 0 : failed to convert, otherwise 1 
 */
static int kdb_str2addr(const char *strp, kdbva_t *addrp, pid_t gpid)
{
    kdbva_t addr;
    char *endp;

    /* assume it's an address */
    KDBGP2("str2addr: str:%s gpid:%d\n", strp, gpid);
    addr = (kdbva_t)simple_strtoul(strp, &endp, 16);   /* handles leading 0x */
    if ( endp != strp+strlen(strp) )    /* failed, check if symbol str */
        if ( !(addr = kdb_sym2addr((char *)strp, gpid)) )
            return 0;

    *addrp = addr;
    KDBGP2("str2addr: addr:0x%lx\n", addr);

    return 1;
}

static int kdb_cpu_valid(int in_cpu)
{
    int cpu;

    for_each_cpu(cpu, cpu_online_mask)
        if (in_cpu == cpu)
            return 1;
    return 0;
}

/* Return: 0 : failed to convert, otherwise 1 */
static int kdb_str2cpu(const char *strp, int *cpup, int perr)
{
    if ( kdb_str2deci(strp, cpup) && kdb_cpu_valid(*cpup) )
        return 1;

    if ( perr )
        kdbxp("cpu:%s not valid\n", strp);

    return 0;
}

static int kdb_tp_valid(struct task_struct *tp, int pr_err)
{
    struct task_struct *t, *p;

    for_each_process(p)
        for_each_thread(p, t)   /* includes parent process/thread */
            if (t == tp)
                return 1;

    if ( pr_err )
        kdbxp("Invalid task struct ptr:%p\n", tp);

    return 0;
}

static struct task_struct *kdb_pid2tp(pid_t pid, int pr_err)
{
    struct task_struct *t, *p;

    for_each_process(p)
        for_each_thread(p, t)   /* includes parent process/thread */
            if (t->pid == pid)
                return t;

    if ( pr_err )
        kdbxp("kdb_pid2tp: pid:%d not found\n", pid);

    return NULL;
}

static struct task_struct *kdb_str2tp(const char *arg, int perr)
{
        struct task_struct *tp;

        if ( !kdb_str2ulong(arg, (ulong *)&tp) ||
             (ulong)tp < PAGE_OFFSET || !kdb_tp_valid(tp, 1) ) 
        {
            if (perr)
                kdbxp("Invalid task struct ptr: %s\n", arg);

            return NULL;
        }
        return tp;
}

/* return: 0 failed. 1 success */
static int kdb_str2pid(const char *strp, pid_t *pid, int perr)
{
    if ( kdb_str2deci(strp, (int *)pid) && kdb_pid2tp(*pid, perr) )
        return 1;       /* success */

    return 0;
}

static int kdb_vcpu_valid(struct kvm_vcpu *vp)
{
    int i;
    struct list_head *lp;

    /* vm_list part of struct kvm in kvm_host.h */
    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list);  /* container of*/

        for (i = 0; i < KVM_MAX_VCPUS; i++) {
            if ( kp->vcpus[i] == vp )
                return 1;
        }
    }
    return 0;
}

static struct kvm_vcpu *kdb_str2vcpu(const char *arg, int perr)
{
    struct kvm_vcpu *vp;

    if ( kdb_str2ulong(arg, (ulong *)&vp) && (ulong)vp >= PAGE_OFFSET && 
         kdb_vcpu_valid(vp) )
        return vp;

    if (perr)
        kdbxp("Invalid vcpu ptr:%s\n", arg);

    return NULL;
}

/* return vcpu ptr for given pid if it's guest pid, else NULL */
struct kvm_vcpu *kdbx_pid_to_vcpu(pid_t pid, int pr_err)
{
    int i;
    struct list_head *lp;
    struct kvm_vcpu *vp;
    struct task_struct *ltp, *tp;

    if ( pid == 0 )
        return NULL;

    tp = kdb_pid2tp(pid, pr_err);

    /* vm_list part of struct kvm in kvm_host.h */
    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list);  /* container of*/

        for (i = 0; i < KVM_MAX_VCPUS; i++) {
            if ( (vp = kp->vcpus[i]) == NULL )
                continue;

            ltp = pid_task(vp->pid, PIDTYPE_PID);
            if ( tp && ltp && tp->pid == ltp->pid )
                return vp;
        }
    }
    if (pr_err)
        kdbxp("pid_to_vcpu: Invalid pid %d\n", pid);

    return NULL;
}

/* given str is either pid or vcpu ptr, convert to vcpu ptr address.
 * return: NULL if not valid pid or vcpu ptr */
static struct kvm_vcpu *kdb_pidvcpustr2vcpu(const char *arg, int pr_err)
{
    pid_t pid;
    struct kvm_vcpu *vp;

    /* first check vp as it's long, and pid is int */
    if ( (vp = kdb_str2vcpu(arg, pr_err)) )
        return vp;

    if ( kdb_str2pid(arg, &pid, pr_err) )
        return kdbx_pid_to_vcpu(pid, pr_err);

    return NULL;
}

static struct kvm *kdbx_str2skvm(const char *kpstr, int perror)
{
    ulong addr;
    struct list_head *lp;

    if (kdb_str2ulong(kpstr, &addr) == 0) {
        if (perror)
            kdbxp("Unable to convert %s to ulong\n", kpstr);
        return NULL;
    }
    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list); /* container of*/

        if ((ulong)kp == addr)
            return kp;
    }
    if (perror)
        kdbxp("Invalid skvm ptr:%lx\n", addr);

    return NULL;
}
#if 0
vp->kvm == struct kvm *
static struct kvm *kdb_vcpu2skvm(struct kvm_vcpu *in_vp, int pr_err)
{
    int i;
    struct list_head *lp;
    struct kvm_vcpu *vp;

    /* vm_list part of struct kvm in kvm_host.h */
    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list);  /* container of*/

        if ( kp == NULL )
            return NULL;

        for (i = 0; i < KVM_MAX_VCPUS; i++) {
            if ( (vp = kp->vcpus[i]) == NULL )
                continue;

            if ( vp == in_vp )
                return kp;
        }
    }
    if (pr_err)
        kdbxp("vcpu2skvm: Invalid vp %p\n", in_vp);

    return NULL;
}
#endif

/* return tgid for given pid */
pid_t kdbx_pid2tgid(pid_t pid)
{
    struct task_struct *tp = kdb_pid2tp(pid, 0);

    if ( tp )
        return tp->tgid;

    return 0;
}

#if 0
/* convert string guest tgid to hex val. 
 * return : true if success. false/0 on failure */
static int kdb_str2gtgid(char *strp, pid_t *tgidp, int perr)
{
    if ( kdb_str2deci(strp, (int *)tgidp) && kdb_pid2tp(*tgidp, perr) &&
         kdbx_pid_to_vcpu(*tgidp, perr) )
    {
        return 1;
    }
    return 0;
}
#endif

static int kdb_gfn_valid(struct kvm_vcpu *vp, ulong gfn, int prerr)
{
#if 0
    struct kvm *skvm = vp ? vp->kvm : NULL;

    if ( skvm == NULL )
        return 0;
#endif
    if ( __gfn_to_memslot(kvm_memslots(vp->kvm), gfn) )
        return 1;

    if (prerr)
        kdbxp("Invalid gfn:%lx\n", gfn);

    return 0;
}

/* return a guest bitness: 32 or 64 */
int kdbx_guest_bitness(pid_t gpid)
{   
    if ( gpid == 0 )
        return 64;      /* host always 64 */

    // kdbxp("FIXME: kdbx_guest_bitness. returning 64 for now\n");
    return 64;
}

/* do vmexit on all cpu's so intel VMCS can be dumped */
void kdbx_cpu_flush_vmcs(int tgt_cpu)
{
    int cpu, ccpu = smp_processor_id();

    if ( tgt_cpu == ccpu ) {
        kdbx_curr_cpu_flush_vmcs();
        return;
    }

    for_each_online_cpu(cpu) {
        if (cpu == tgt_cpu) {
            int savcmd = kdbx_cpu_cmd[cpu];

#if 0   /* could be called from read_mem() with SHOW_PC command */
            if (kdbx_cpu_cmd[cpu] != KDB_CPU_PAUSE){  /* hung cpu */
                kdbxp("[%d]Skipping (hung?) cpu:%d cmd:%d\n", ccpu, cpu, 
                      kdbx_cpu_cmd[cpu]);
                continue;
            }
#endif
            kdbx_cpu_cmd[cpu] = KDB_CPU_DO_VMEXIT;
            while (kdbx_cpu_cmd[cpu] == KDB_CPU_DO_VMEXIT);
            kdbx_cpu_cmd[cpu] = savcmd;
            return;
        }
    }
}

ulong kdbx_get_hvm_field(struct kvm_vcpu *vp, uint field)
{
    if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL) { 
        kdbxp("kdbx_get_hvm_field: FIXME on AMD\n");
        return 0xdeadbeefdeadbeef;
    }
    // kdb_all_cpu_flush_vmcs();

    return kdbx_get_vmcs_field(vp, field);
}


/* kdb_on_host_rsp will not work because there is no stack switch upon exception
 * in host code executing on vexit */
int kdbx_guest_mode(struct pt_regs *regs)
{
    return !!( regs->flags & ((ulong)1 << KDBX_GUEST_MODE_BIT) );
}

#if 0
/* upon vmexit, host running on vmx_vcpu->host_sp */
int kdb_on_host_rsp(struct pt_regs *regs)
{
    int i;
    struct list_head *lp;
    struct kvm_vcpu *vp;
    ulong host_sp;
    ulong check_mask = ~(ulong)0xffff;  /* try checking for 64k */

    /* vm_list part of struct kvm in kvm_host.h */
    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list);  /* container of*/

        if ( kp == NULL )
            break;

        for (i = 0; i < KVM_MAX_VCPUS; i++) {
            if ( (vp = kp->vcpus[i]) == NULL )
                continue;

            host_sp = kdbx_get_hvm_field(vp, HOST_RSP);
            if ( (host_sp & check_mask) == ((ulong)regs & check_mask) )
                return 1;
        }
    }
    return 0;
}
#endif

/* kdbx always caches VCPU_REGS_RIP/VCPU_REGS_RSP upon vmexit */
void kdbx_display_pc(struct pt_regs *regs)
{  
    if ( kdbx_guest_mode(regs) ) {
        struct kvm_vcpu *vp = kdbx_pid_to_vcpu(current->pid, 0);
        ulong ip = vp ? vp->arch.regs[VCPU_REGS_RIP] : 0;
        pid_t gpid = current->pid;

        if ( vp == NULL ) {
            kdbxp("guest_mode regs:%p has no vcpu\n", regs);
            return;
        }
        kdbx_print_instr(ip, 1, gpid);
    } else 
        kdbx_print_instr(regs->KDBIP, 1, 0);
}

/* kdb_print_spin_lock(&xyz_lock, "xyz_lock:", "\n"); */
static void kdb_print_spin_lock(char *strp, spinlock_t *lkp, char *nlp)
{
    arch_spinlock_t *alp = &lkp->rlock.raw_lock;

#ifdef CONFIG_QUEUED_SPINLOCKS
    kdbxp("%s val:%x\n", strp, alp->val.counter);
#else
    kdbxp("%s union {head_tail: %04hx tickets.head:%x tail:%x} %s", strp,
         alp->head_tail, alp->tickets.head, alp->tickets.tail, nlp);
#endif

#ifdef CONFIG_DEBUG_SPINLOCK
    kdbxp("   magic:%x owner_cpu:%d\n", lkp->rlock.magic, lkp->rlock.owner_cpu);
#endif
}

/* check if register string is valid. if yes, return offset to the register
 * in pt_regs, else return -1 */
static int kdb_valid_reg(const char *nmp) 
{
    int i;
    for (i=0; i < sizeof(kdb_reg_nm_offs)/sizeof(kdb_reg_nm_offs[0]); i++)
        if (strcmp(kdb_reg_nm_offs[i].reg_nm, nmp) == 0)
            return kdb_reg_nm_offs[i].reg_offs;
    return -1;
}

/* given offset of register, return register name string. if offset is invalid
 * return NULL */
static char *kdb_regoffs_to_name(int offs)
{
    int i;

    for (i=0; i < sizeof(kdb_reg_nm_offs)/sizeof(kdb_reg_nm_offs[0]); i++)
        if (kdb_reg_nm_offs[i].reg_offs == offs)
            return kdb_reg_nm_offs[i].reg_nm;
    return NULL;
}

void kdbx_vcpu_to_ptregs(struct kvm_vcpu *vp, struct pt_regs *regs)
{
    regs->r15 = vp->arch.regs[VCPU_REGS_R15];
    regs->r14 = vp->arch.regs[VCPU_REGS_R14];
    regs->r13 = vp->arch.regs[VCPU_REGS_R13];
    regs->r12 = vp->arch.regs[VCPU_REGS_R12];
    regs->bp = vp->arch.regs[VCPU_REGS_RBP];
    regs->bx = vp->arch.regs[VCPU_REGS_RBX];
    regs->r11 = vp->arch.regs[VCPU_REGS_R11];
    regs->r10 = vp->arch.regs[VCPU_REGS_R10];
    regs->r9 = vp->arch.regs[VCPU_REGS_R9];
    regs->r8 = vp->arch.regs[VCPU_REGS_R8];
    regs->ax = vp->arch.regs[VCPU_REGS_RAX];
    regs->cx = vp->arch.regs[VCPU_REGS_RCX];
    regs->dx = vp->arch.regs[VCPU_REGS_RDX];
    regs->si = vp->arch.regs[VCPU_REGS_RSI];
    regs->di = vp->arch.regs[VCPU_REGS_RDI];
    regs->ip = vp->arch.regs[VCPU_REGS_RIP];
}

void kdbx_ptregs_to_vcpu(struct kvm_vcpu *vp, struct pt_regs *regs)
{
    vp->arch.regs[VCPU_REGS_R15] = regs->r15;
    vp->arch.regs[VCPU_REGS_R14] = regs->r14;
    vp->arch.regs[VCPU_REGS_R13] = regs->r13;
    vp->arch.regs[VCPU_REGS_R12] = regs->r12;
    vp->arch.regs[VCPU_REGS_RBP] = regs->bp;
    vp->arch.regs[VCPU_REGS_RBX] = regs->bx;
    vp->arch.regs[VCPU_REGS_R11] = regs->r11;
    vp->arch.regs[VCPU_REGS_R10] = regs->r10;
    vp->arch.regs[VCPU_REGS_R9] = regs->r9;
    vp->arch.regs[VCPU_REGS_R8] = regs->r8;
    vp->arch.regs[VCPU_REGS_RAX] = regs->ax;
    vp->arch.regs[VCPU_REGS_RCX] = regs->cx;
    vp->arch.regs[VCPU_REGS_RDX] = regs->dx;
    vp->arch.regs[VCPU_REGS_RSI] = regs->si;
    vp->arch.regs[VCPU_REGS_RDI] = regs->di;
    vp->arch.regs[VCPU_REGS_RIP] = regs->ip;
}

static char *kdb_cpu_cmd_str(int cpu)
{
    switch (cpu) {
        case KDB_CPU_INVAL:
            return "KDB_CPU_INVAL";
        case KDB_CPU_QUIT:       
            return "KDB_CPU_QUIT";       
        case KDB_CPU_PAUSE:     
            return "KDB_CPU_PAUSE";     
#if 0
        case KDB_CPU_DISABLE:  
            return "KDB_CPU_DISABLE";  
#endif
        case KDB_CPU_SHOWPC:  
            return "KDB_CPU_SHOWPC";  
        case KDB_CPU_SHOW_CUR:  
            return "KDB_CPU_SHOW_CUR";  
        case KDB_CPU_DO_VMEXIT:   
            return "KDB_CPU_DO_VMEXIT";   
        case KDB_CPU_MAIN_KDB:   
            return "KDB_CPU_MAIN_KDB";   
        case KDB_CPU_GO:        
            return "KDB_CPU_GO";        
        case KDB_CPU_SS:       
            return "KDB_CPU_SS";       
        case KDB_CPU_NI:         
            return "KDB_CPU_NI";         
        case KDB_CPU_INSTALL_BP:  
            return "KDB_CPU_INSTALL_BP";  
    }
    return "???";
}

/* ===================== util struct funcs ================================= */
#if 0
static void kdb_prnt_timer(struct timer *tp)
{
    kdbxp(" expires:%016lx cpu:%d status:%x\n", tp->expires, tp->cpu,tp->status);
    kdbxp(" function data:%p ptr:%p ", tp->data, tp->function);
    kdbx_prnt_addr2sym(DOMID_IDLE, (kdbva_t)tp->function, "\n");
}

static void kdb_prnt_periodic_time(void)
{
    kdbxp(" next:%p prev:%p\n", ptp->list.next, ptp->list.prev);
    kdbxp(" on_list:%d one_shot:%d dont_freeze:%d irq_issued:%d src:%x irq:%x\n",
         ptp->on_list, ptp->one_shot, ptp->do_not_freeze, ptp->irq_issued,
         ptp->source, ptp->irq);
    kdbxp(" vcpu:%p pending_intr_nr:%08x period:%016lx\n", ptp->vcpu,
         ptp->pending_intr_nr, ptp->period);
    kdbxp(" scheduled:%016lx last_plt_gtime:%016lx\n", ptp->scheduled,
         ptp->last_plt_gtime);
    kdbxp(" \n          timer info:\n");
    kdb_prnt_timer(&ptp->timer);
    kdbxp("\n");
}
#endif

static char *kdbx_virtdev_to_str(int dev)
{
    switch (dev) {
        case VIRTIO_ID_NET:
            return "VIRTIO_ID_NET";
        case VIRTIO_ID_BLOCK:
            return "VIRTIO_ID_BLOCK";
        case VIRTIO_ID_CONSOLE:
            return "VIRTIO_ID_CONSOLE";
        case VIRTIO_ID_RNG:
            return "VIRTIO_ID_RNG";
        case VIRTIO_ID_BALLOON:
            return "VIRTIO_ID_BALLOON";
        case VIRTIO_ID_RPMSG:
            return "VIRTIO_ID_RPMSG";
        case VIRTIO_ID_SCSI:
            return "VIRTIO_ID_SCSI";
        case VIRTIO_ID_9P:
            return "VIRTIO_ID_9P";
        case VIRTIO_ID_RPROC_SERIAL:
            return "VIRTIO_ID_RPROC_SERIAL";
        case VIRTIO_ID_CAIF:
            return "VIRTIO_ID_CAIF";
        case VIRTIO_ID_GPU:
            return "VIRTIO_ID_GPU";
        case VIRTIO_ID_INPUT:
            return "VIRTIO_ID_INPUT";
        case VIRTIO_ID_VSOCK:
            return "VIRTIO_ID_VSOCK";
        case VIRTIO_ID_CRYPTO:
            return "VIRTIO_ID_CRYPTO";
    }
    return "??";
}

/* ===================== cmd functions  ==================================== */

static kdbx_cpu_cmd_t kdb_usgf_slk(void)
{
    kdbxp("slk addr : show simple lock details\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_slk(int argc, const char **argv, struct pt_regs *regs)
{
    ulong addr;

    if (argc != 2)
        return kdb_usgf_slk();

    if ( !kdb_str2addr(argv[1], &addr, 0) ) {
        kdbxp("kdb:Invalid addr\n");
        return KDB_CPU_MAIN_KDB;
    }
    kdb_print_spin_lock("spinlock:", (spinlock_t *)addr, "\n");
    return KDB_CPU_MAIN_KDB;
}

/* FUNCTION: disassemble */
static kdbx_cpu_cmd_t kdb_usgf_dis(void)
{
    kdbxp("dis [addr|sym][num][pid]: Disassemble instrs\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_dis(int argc, const char **argv, struct pt_regs *regs)
{
    static kdbva_t addr = BFD_INVAL;
    static pid_t gpid = 0;
    int num = 16;                      /* default num of instrs to display */

    if (argc == -1) {           /* command repeat */
        addr = kdbx_print_instr(addr, num, gpid);
        return KDB_CPU_MAIN_KDB;
    }

    gpid = -1;   /* no command repeat, reset pid */

    if (argc >= 4 && !kdb_str2pid(argv[3], &gpid, 1)) { 
        return KDB_CPU_MAIN_KDB;
    } 
    if (argc >= 3 && !kdb_str2deci(argv[2], &num)) {
        kdbxp("kdb:Invalid num\n");
        return KDB_CPU_MAIN_KDB;
    } 
    if ( num > 128 ) {
        kdbxp("sorry, num should be <= 128\n");
        return KDB_CPU_MAIN_KDB;
    }

    if ( gpid == -1 ) {       /* user didn't enter pid */
        if ( kdbx_guest_mode(regs) )
            gpid = current->pid;
        else
            gpid = 0;        /* regs->ip is in host */
    } else {
        if ( !kdbx_pid_to_vcpu(gpid, 0) )
            gpid = 0;        /* pid in host */
    }

    if (argc >= 2 && !kdb_str2addr(argv[1], &addr, gpid)) {
        kdbxp("kdb:Invalid addr/sym\n");
        return KDB_CPU_MAIN_KDB;
    } 
    if ( argc == 1 )                    /* not command repeat */
        addr = regs->KDBIP;             /* PC is the default */
    else if ( addr == BFD_INVAL ) {
        kdbxp("kdb:Invalid addr/sym\n");
        return KDB_CPU_MAIN_KDB;
    }
    addr = kdbx_print_instr(addr, num, gpid);

    return KDB_CPU_MAIN_KDB;
}

/* FUNCTION: kdb_cmdf_dism() Toggle disassembly syntax from Intel to ATT/GAS */
static kdbx_cpu_cmd_t kdb_usgf_dism(void)
{
    kdbxp("dism: toggle disassembly mode between ATT/GAS and INTEL\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_dism(int argc, const char **argv, struct pt_regs *regs)
{
    kdbx_toggle_dis_syntax();
    return KDB_CPU_MAIN_KDB;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,35)
void kdbx_show_stack(struct pt_regs *regs, pid_t pid, int prmax)
{
    ulong spval, *sp_ptr;
    kdbva_t ip = 0; 
    int numrd, printed, sz = sizeof(ulong);
    struct kvm_vcpu *vp = NULL;
    pid_t gpid = 0;

    if ( current->pid == pid ) {
        if ( kdbx_guest_mode(regs) ) {
            vp = kdbx_pid_to_vcpu(pid, 0);
            gpid = pid;
        }
    } else {
        vp = kdbx_pid_to_vcpu(pid, 0);
        gpid = vp ? pid : 0;
    }
    if ( vp ) {
        /* kdbx always caches VCPU_REGS_RIP/VCPU_REGS_RSP upon vmexit */
        ip = vp->arch.regs[VCPU_REGS_RIP];
        sp_ptr = (ulong *)vp->arch.regs[VCPU_REGS_RSP];
    } else if ( current->pid == pid || pid == 0 ) {
        ip = regs->ip;
        sp_ptr = (ulong *)regs->sp;
    } else {
        struct task_struct *tp = kdb_pid2tp(pid, 0);

        ip = 0;
        sp_ptr = (ulong *)tp->thread.sp;
    }
    KDBGP("f_f: pid:%d gpid:%d gmode:%d vp:%p ip:%lx sp_ptr:%lx\n", pid, gpid,
          kdbx_guest_mode(regs), vp, ip, sp_ptr);

    if ( ip )
        kdbx_print_instr(ip, 1, gpid);

    if ( gpid && !kdbx_guest_sym_loaded(gpid) )
        return;

    for (printed = 0; printed < prmax; sp_ptr++) {

        numrd = kdbx_read_mem((kdbva_t)sp_ptr, (kdbbyt_t *)&spval, sz, vp);
        KDBGP1("sp_ptr:%lx sz:%d vp:%lx numrd:%d\n", sp_ptr, sz, vp, numrd);
        if (numrd != sz) 
            return;

        if ( kdbx_text_addr(spval, gpid) ) {
            kdbx_print_instr(spval, 1, gpid);
            printed++;
        }
    }
}

#else  /*  LINUX_VERSION_CODE < KERNEL_VERSION(4,14,35) */

/* common_interrupt: will put the interrupted thread kernel sp at the very
 * bottom/start of the irq stack */
static ulong *kdbx_saved_sp_on_irq_stack(void)
{
    ulong *start   = (ulong *)this_cpu_read(irq_stack_ptr);

    /* remember, push first decrements then pushes */
    return ((ulong *)*(start - 1));
}

/* irq_stack_ptr is initialized to irq_stack_union + IRQ_STACK_SIZE */
static int kdbx_in_irq_stack(ulong *spaddr)
{
    /* starts at the start and grows DOWN to end */
    ulong *highaddr   = (unsigned long *)this_cpu_read(irq_stack_ptr);
    ulong *lowaddr = highaddr - (IRQ_STACK_SIZE / sizeof(long));

    return (spaddr >= lowaddr && spaddr <= highaddr);
}

static int kdbx_in_thread_stack(ulong *spaddr, struct task_struct *tp)
{
    ulong *lowaddr = task_stack_page(tp);
    ulong *highaddr = task_stack_page(tp) + THREAD_SIZE;

    /* top of stack: ffffc900031cc000, so it starts at ffffc900031cbfff */
    return (spaddr >= lowaddr && spaddr < highaddr); /* NOT <= */
}

#if 0
static void kdbx_dump_bp_stack(ulong *spaddr, struct pt_regs *regs,
                               struct task_struct *tp)
{
    ulong sp, spval;
    int numrd, printed, sz = sizeof(ulong);
    struct unwind_state state;
    struct stack_info stack_info = {0};
    unsigned long visit_mask = 0;
    int graph_idx = 0;
    bool partial = false;
    int sav_on_cpu = -1;

    if ( tp != current ) {
        regs = NULL;
        sav_on_cpu = tp->on_cpu;
        tp->on_cpu = 0;  /* for __unwind_start -> task_on_another_cpu */
    }

    unwind_start(&state, tp, regs, spaddr);
    regs = unwind_get_entry_regs(&state, &partial);

    for ( ; spaddr; spaddr = PTR_ALIGN(stack_info.next_sp, sizeof(long))) {
        const char *stack_name;

        if (get_stack_info(spaddr, task, &stack_info, &visit_mask)) {
            /*
             * We weren't on a valid stack.  It's possible that
             * we overflowed a valid stack into a guard page.
             * See if the next page up is valid so that we can
             * generate some kind of backtrace if this happens.
            */
            spaddr = (unsigned long *)PAGE_ALIGN((unsigned long)spaddr);
            if (get_stack_info(spaddr, task, &stack_info, &visit_mask))
                break;
        }

        stack_name = stack_type_name(stack_info.type);
        if (stack_name)
            kdbxp("Stack type: %s\n", stack_name);

        /*
         * Scan the stack, printing any text addresses we find.  At the
         * same time, follow proper stack frames with the unwinder.
         *
         * Addresses found during the scan which are not reported by
         * the unwinder are considered to be additional clues which are
         * sometimes useful for debugging and are prefixed with '?'.
         * This also serves as a failsafe option in case the unwinder
         * goes off in the weeds.
        */
        for (; spaddr < stack_info.end; spaddr++) {
            unsigned long real_addr;
            int reliable = 0;
            unsigned long addr = READ_ONCE_NOCHECK(*spaddr);
            unsigned long *ret_addr_p = unwind_get_return_address_ptr(&state);

            if (!__kernel_text_address(addr))
                continue;

            if (spaddr == ret_addr_p)
                reliable = 1;

            /*
             * When function graph tracing is enabled for a
             * function, its return address on the stack is
             * replaced with the address of an ftrace handler
             * (return_to_handler).  In that case, before printing
             * the "real" address, we want to print the handler
             * address as an "unreliable" hint that function graph
             * tracing was involved.
            */
            real_addr = ftrace_graph_ret_addr(task, &graph_idx, addr, spaddr);
#if 0
            if (real_addr != addr) {
                kdxp("? ");
                kdbx_print_instr(addr, 1, 0);
            }
#endif
            kdbx_print_instr(real_addr, 1, 0);

            if (!reliable)
                continue;
next:
            /*
             * Get the next frame from the unwinder.  No need to
             * check for an error: if anything goes wrong, the rest
             * of the addresses will just be printed as unreliable.
            */
            unwind_next_frame(&state);

            /* if the frame has entry regs, print them */
            regs = unwind_get_entry_regs(&state, &partial);
            if (regs)
                kdbx_print_regs(regs);
                show_regs_if_on_stack(&stack_info, regs, partial);
        }
        if (stack_name)
            kdbxp("Stack type: %s\n", stack_name);
   }
}
#endif /* #if 0 */

#ifdef CONFIG_FRAME_POINTER
/* NOT called for guest */
static void kdbx_walk_bp_stack(ulong regbp, struct task_struct *tp)
{
    while (kdbx_in_thread_stack((ulong *)regbp, tp)) {
        ulong ip = *((ulong *)regbp + 1);
        regbp = *((ulong *)regbp);

        if ( ip ) {
            if ( kdbx_text_addr(ip, 0) )
                kdbx_print_instr(ip, 1, 0);
        } else
            break;
    }
}
#endif /* CONFIG_FRAME_POINTER */

/* called for both host and guest */
static void kdbx_walk_sp_stack(ulong *spaddr, int irqstack, struct kvm_vcpu *vp,
                               pid_t gpid, struct task_struct *tp, int max)
{
    ulong spval;
    int numrd, printed, sz = sizeof(ulong);

    for (printed = 0; printed < max; spaddr++) 
    {
        if ( irqstack ) {
            if ( !kdbx_in_irq_stack(spaddr) )
                return;
        } else {
            if ( tp && !kdbx_in_thread_stack(spaddr, tp) ) 
                return;
        }
        numrd = kdbx_read_mem((kdbva_t)spaddr, (kdbbyt_t *)&spval, sz, vp);
        KDBGP1("spaddr:%lx sz:%d vp:%lx numrd:%d\n", spaddr, sz, vp, numrd);
        if (numrd != sz) 
            return;

        if ( kdbx_text_addr(spval, gpid) ) {
            kdbx_print_instr(spval, 1, gpid);
            printed++;
        }
    }
}

ulong *kdbx_show_irq_stack(ulong *spaddr)
{
    kdbx_walk_sp_stack(spaddr, 1, NULL, 0, NULL, 32);
    return kdbx_saved_sp_on_irq_stack();
}

char *kdx_stack_type_name(enum stack_type type)
{
    switch (type) {
        case STACK_TYPE_UNKNOWN:
            return "UNKNOWN";
        case STACK_TYPE_TASK:
            return "Task";
        case STACK_TYPE_SOFTIRQ:
            return "SoftIRQ";
        default:
            return (char *)stack_type_name(type);
    }
    return NULL;
}

/* dump one stack type: irq, exception, task, etc.. and return ptr to regs to
 * interrupted process. NOT called for guest */
struct pt_regs *kdbx_dump_type_stack(kdbva_t ip, struct pt_regs *regs,
                                     ulong *spaddr, struct task_struct *tp,
                                     int max)
{
    struct stack_info stack_info;
    enum stack_type st;

    /* check if stack is task, irq, exception, entry, softirq, ... */
    get_stack_info(spaddr, tp, &stack_info, NULL);
    st = stack_info.type;

    KDBGP("dumpst: st:%d spaddr:%lx regs:%p\n", st, spaddr, regs);

    kdbxp("Stack type: %s\n", kdx_stack_type_name(st));
    if ( ip )
        kdbx_print_instr(ip, 1, 0);

#ifdef CONFIG_FRAME_POINTER
    /* if the user set bp very beginning of function, then rbp is not yet set.
     * usually, bp is set very near the top, so check 2-3 words for caller IP */
    {int i;
    for (i=0; i < 3; i++, spaddr++) {
        ulong spval = *spaddr;   /* remember, this is not called for guests */

        if (kdbx_text_addr(spval, 0))
            kdbx_print_instr(spval, 1, 0);
    }
    }
    if ( regs == NULL || regs->bp ==  0 )
        return NULL;    /* ef it :) */
    kdbx_walk_bp_stack(regs->bp, tp);
    // kdbxp("--- Now showing sp stack for debug ---- \n");
    // kdbx_walk_sp_stack(spaddr, 0, NULL, 0, tp, 20);
#else
    kdbx_walk_sp_stack(spaddr, 0, vp, gpid, tp, prmax);
#endif

    /* task_pt_regs is not interesting to us because that is where the context
     * of say user thread is stored */
    if ( st == STACK_TYPE_TASK || st == STACK_TYPE_UNKNOWN )
        return NULL;

    if ( st == STACK_TYPE_IRQ ) {
        ulong *end   = (unsigned long *)this_cpu_read(irq_stack_ptr);
        struct pt_regs *regs  = (struct pt_regs *)end - 1;

        return regs;
    }
    if ( st >= STACK_TYPE_EXCEPTION && st < N_EXCEPTION_STACKS) {
        int idx = st - STACK_TYPE_IRQ;
        ulong *end   = (ulong *)raw_cpu_ptr(&orig_ist)->ist[idx];

        regs  = (struct pt_regs *)end - 1;
        return regs;
    }
    return NULL;
}

/* 
 * cpu_entry_stack is per cpu 512 byte area. TSS is initialized to this for 
 * each cpu. Upon, interrupt/exception, tss.sp0 is used by cpu for stack. This
 * is the cpu_entry_stack, aka, entry trampoline. Then common_interrupt will 
 * switch to kernel thread stack top/beginning and save context, then switch 
 * to thread kernel stack before calling do_IRQ.
 * In kdbx, we are mostly intrested in the top/current frame. 
 */
void kdbx_show_stack(struct pt_regs *regs, pid_t pid, int prmax)
{
    ulong *spaddr;
    struct task_struct *tp = NULL;
    kdbva_t ip = 0; 
    struct kvm_vcpu *vp = NULL;
    pid_t gpid = 0;

    if ( (vp = kdbx_pid_to_vcpu(pid, 0)) )
        gpid = pid;

    if ( vp ) {
        /* kdbx always caches VCPU_REGS_RIP/VCPU_REGS_RSP upon vmexit */
        ip = vp->arch.regs[VCPU_REGS_RIP];
        spaddr = (ulong *)vp->arch.regs[VCPU_REGS_RSP];
    } else if ( current->pid == pid || pid == 0 ) {
        ip = regs->ip;
        spaddr = (ulong *)regs->sp;
        tp = current;
    } else {
        tp = kdb_pid2tp(pid, 0);
        ip = 0;
        spaddr = (ulong *)tp->thread.sp;
    }
    KDBGP("sstk: pid:%d gpid:%d gmode:%d vp:%p ip:%lx spaddr:%lx\n", pid, gpid,
          kdbx_guest_mode(regs), vp, ip, spaddr);

    if ( gpid ) {
        if ( !kdbx_guest_sym_loaded(gpid) )
            return;
        else {
            kdbxp("Note: Guest stack does not use frame pointer\n");
            if ( ip )
                kdbx_print_instr(ip, 1, gpid);
            kdbx_walk_sp_stack(spaddr, 0, vp, gpid, tp, prmax);
            return;
        }
    }

    /* now don't go more than two types, kdbx really doesn't care beyond */
    regs = kdbx_dump_type_stack(ip, regs, spaddr, tp, prmax);
    if ( regs )
        kdbx_dump_type_stack(ip, regs, spaddr, tp, prmax);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,14,35) */


/* display stack. if vcpu ptr given, then display stack for that. Otherwise,
 * use current regs */
static kdbx_cpu_cmd_t kdb_usgf_f(void)
{
    kdbxp("f [pid] [m #]: dump current stack. m # for max frames\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_f(int argc, const char **argv, struct pt_regs *regs)
{
    int max = 24;
    pid_t pid = kdbx_guest_mode(regs) ? current->pid : 0;

    if ( argc > 4 )
        return kdb_usgf_f();

    if (argc > 1 ) {
        if ( *argv[1] == '0' ) {
            pid = 0;      /* always allow host pid override */
        } else if ( !kdb_str2pid(argv[1], &pid, 1) ) {
            if ( (*argv[1] !=  'm') || argc != 3 || 
                 !kdb_str2deci(argv[2], &max))
            {
                return KDB_CPU_MAIN_KDB;
            }
        } else if (argc == 2 ) {
            ;      /* 2 args are ok with valid pid */
        } else if (argc < 4 || (*argv[2] != 'm') || 
                   !kdb_str2deci(argv[3], &max))
        {
                return KDB_CPU_MAIN_KDB;
        }
    }
    kdbx_show_stack(regs, pid, max);
    return KDB_CPU_MAIN_KDB;
}

/* Display kdb stack. for debugging kdb itself */
static kdbx_cpu_cmd_t kdb_usgf_kdbf(void)
{
    kdbxp("kdbf: display kdb stack. for debugging kdb only\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_kdbf(int argc, const char **argv, struct pt_regs *regs)
{
    kdbx_trap_immed(KDBX_TRAP_KDBSTACK);
    return KDB_CPU_MAIN_KDB;
}

/* worker function to display memory.  address could be machine or virtual */
static void
_kdb_display_mem(kdbva_t *addrp, int *lenp, int wordsz, pid_t pid, int is_maddr)
{
    kdbbyt_t *buf = kdb_membuf, *bp;
    int numrd, bytes;
    int len = *lenp;
    kdbva_t addr = *addrp;
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(pid, 0);

    /* round len down to wordsz boundry because on intel endian, printing
     * characters is not prudent, (long and ints can't be interpreted 
     * easily) */
    len &= ~(wordsz-1);
    len = KDBMIN(DDBUFSZ, len);
    len = len ? len : wordsz;

    KDBGP("dmem:addr:%lx buf:%p len:$%d sz:$%d pid:%d maddr:%d\n", addr,
          buf, len, wordsz, pid, is_maddr);
    if (is_maddr)
        numrd = kdbx_read_mmem((kdbma_t)addr, buf, len);
    else
        numrd = kdbx_read_mem(addr, buf, len, vp);

    if ( numrd > len ) {
        kdbxp("Memory read error. len:%d Bytes read:$%d\n", len, numrd);
        return;
    }

    for (bp = buf; numrd > 0;) {
        kdbxp("%016lx: ", addr); 

        /* display 16 bytes per line */
        for (bytes=0; bytes < 16 && numrd > 0; bytes += wordsz) {
            if (numrd >= wordsz) {
                if (wordsz == 8)
                    kdbxp(" %016lx", *(long *)bp);
                else
                    kdbxp(" %08x", *(int *)bp);
                bp += wordsz;
                numrd -= wordsz;
                addr += wordsz;
            }
        }
        kdbxp("\n");
        continue;
    }
    *lenp = len;
    *addrp = addr;
}

/* display machine mem, ie, the given address is machine address */
static kdbx_cpu_cmd_t 
kdb_display_mmem(int argc, const char **argv, int wordsz, kdbx_usgf_t usg_fp)
{
    static kdbma_t maddr;
    static int len;

    if (argc == -1) {
        _kdb_display_mem(&maddr, &len, wordsz, 0, 1);  /* cmd repeat */
        return KDB_CPU_MAIN_KDB;
    }
    if (argc <= 1 || *argv[1] == '?')
        return (*usg_fp)();

    /* check if num of bytes to display is given by user */
    if (argc >= 3) {
        if (!kdb_str2deci(argv[2], &len)) {
            kdbxp("Invalid length:%s\n", argv[2]);
            return KDB_CPU_MAIN_KDB;
        } 
    } else
        len = 32;                                     /* default read len */

    if (!kdb_str2ulong(argv[1], &maddr)) {
        kdbxp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    _kdb_display_mem(&maddr, &len, wordsz, 0, 1);
    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Dispaly machine Memory Word
 */
static kdbx_cpu_cmd_t kdb_usgf_dwm(void)
{
    kdbxp("dwm:  maddr|sym [num] : dump memory word given machine addr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_dwm(int argc, const char **argv, struct pt_regs *regs)
{
    return kdb_display_mmem(argc, argv, 4, kdb_usgf_dwm);
}

/* 
 * FUNCTION: Dispaly machine Memory DoubleWord 
 */
static kdbx_cpu_cmd_t kdb_usgf_ddm(void)
{
    kdbxp("ddm:  maddr|sym [num] : dump double word given machine addr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_ddm(int argc, const char **argv, struct pt_regs *regs)
{
    return kdb_display_mmem(argc, argv, 8, kdb_usgf_ddm);
}

/* 
 * FUNCTION: Dispaly Memory : word or doubleword
 *           wordsz : bytes in word. 4 or 8
 *
 *           We display upto BUFSZ bytes. User can just press enter for more.
 *           addr is always in hex with or without leading 0x
 */
static kdbx_cpu_cmd_t 
kdb_display_mem(int argc, const char **argv, int wordsz, kdbx_usgf_t usg_fp)
{
    static kdbva_t addr;
    static int len;
    static pid_t gpid = 0;       /* 0 ==> host, non-zero ==> guest */

    if (argc == -1) {
        _kdb_display_mem(&addr, &len, wordsz, gpid, 0);  /* cmd repeat */
        return KDB_CPU_MAIN_KDB;
    }
    if (argc <= 1 || *argv[1] == '?')
        return (*usg_fp)();

    gpid = 0;               /* not a command repeat, re set static gpid again */
    if (argc >= 4) {
        if ( !kdb_str2pid(argv[3], &gpid, 1) )
            return KDB_CPU_MAIN_KDB;
    }

    gpid = kdbx_pid_to_vcpu(gpid, 0) ? gpid : 0;

    /* check if num of bytes to display is given by user */
    if (argc >= 3) {
        if (!kdb_str2deci(argv[2], &len)) {
            kdbxp("Invalid length:%s\n", argv[2]);
            return KDB_CPU_MAIN_KDB;
        } 
    } else
        len = 32;                       /* default read len */

    if (!kdb_str2addr(argv[1], &addr, gpid)) {
        kdbxp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }

    _kdb_display_mem(&addr, &len, wordsz, gpid, 0);
    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Dispaly Memory Word
 */
static kdbx_cpu_cmd_t kdb_usgf_dw(void)
{
    kdbxp("dw vaddr|sym [num][pid]: display word. num required for pid\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_dw(int argc, const char **argv, struct pt_regs *regs)
{
    return kdb_display_mem(argc, argv, 4, kdb_usgf_dw);
}

/* 
 * FUNCTION: Dispaly Memory DoubleWord 
 */
static kdbx_cpu_cmd_t kdb_usgf_dd(void)
{
    kdbxp("dd vaddr|sym [num][pid]: display dword. num required for pid\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_dd(int argc, const char **argv, struct pt_regs *regs)
{
    return kdb_display_mem(argc, argv, 8, kdb_usgf_dd);
}

static kdbx_cpu_cmd_t kdb_usgf_mw(void)
{
    kdbxp("mw vaddr|sym val [pid]: modify memory word in vaddr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_mw(int argc, const char **argv, struct pt_regs *regs)
{
    ulong val;
    kdbva_t addr;
    pid_t gpid = 0;
    struct kvm_vcpu *vp = NULL;

    if (argc < 3) {
        return kdb_usgf_mw();
    }
    if (argc >=4) {
        if (!kdb_str2pid(argv[3], &gpid, 1))
            return KDB_CPU_MAIN_KDB;

        vp = kdbx_pid_to_vcpu(gpid, 1);
        if (vp == NULL)
            return KDB_CPU_MAIN_KDB;
    }

    if (!kdb_str2ulong(argv[2], &val)) {
        kdbxp("Invalid val: %s\n", argv[2]);
        return KDB_CPU_MAIN_KDB;
    }
    if (!kdb_str2addr(argv[1], &addr, gpid)) {
        kdbxp("Invalid addr/sym: %s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    if (kdbx_write_mem(addr, (kdbbyt_t *)&val, 4, vp) != 4)
        kdbxp("Unable to set 0x%lx to 0x%lx\n", addr, val);

    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Modify Memory DoubleWord 
 */
static kdbx_cpu_cmd_t kdb_usgf_md(void)
{
    kdbxp("md vaddr|sym val [pid]: modify memory dword in vaddr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_md(int argc, const char **argv, struct pt_regs *regs)
{
    pid_t gpid;
    ulong val;
    kdbva_t addr;
    struct kvm_vcpu *vp;

    if (argc < 3) {
        return kdb_usgf_md();
    }
    if (argc >=4) {
        if (!kdb_str2pid(argv[3], &gpid, 1))
            return KDB_CPU_MAIN_KDB;
    } else 
        gpid = current->pid;

    gpid = (vp = kdbx_pid_to_vcpu(gpid, 0)) ? gpid : 0;

    if (!kdb_str2ulong(argv[2], &val)) {
        kdbxp("Invalid val: %s\n", argv[2]);
        return KDB_CPU_MAIN_KDB;
    }
    if (!kdb_str2addr(argv[1], &addr, gpid)) {
        kdbxp("Invalid addr/sym: %s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    if (kdbx_write_mem(addr, (kdbbyt_t *)&val, sizeof(val), vp) != sizeof(val))
        kdbxp("Unable to set 0x%lx to 0x%lx\n", addr, val);

    return KDB_CPU_MAIN_KDB;
}

static ulong kdbx_read_cr3(void)
{
    unsigned long val;

    asm volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
    return val;
}

/* see force_reload_TR() in: arch/x86/include/asm/desc.h */
static void kdbx_dump_tss(void)
{
    tss_desc tssdesc;
    ulong ul;
    struct tss_struct *tsss;
    struct x86_hw_tss *tss;
    struct desc_struct *d = get_current_gdt_ro();
 
    /* NOTE: gdb[] entries are not all 8 bytes. 0-7 are each 8 bytes, but 
     *       TSS is 16 bytes */

    memcpy(&tssdesc, &d[GDT_ENTRY_TSS], sizeof(tss_desc));
    ul = (ulong)tssdesc.base0 | (ulong)tssdesc.base1 << 16 | 
         (ulong) tssdesc.base2 << 24 | (ulong)tssdesc.base3 << 32;

    tsss = (struct tss_struct *)ul;
    tss = &tsss->x86_tss;
    kdbxp("tss entry at:%p  gives seg address: %p\n", &d[GDT_ENTRY_TSS], tss);
    kdbxp(" sp0: %016lx  sp1: %016lx  sp2: %016lx\n",
          tss->sp0, tss->sp1, tss->sp2);

    kdbxp(" note: index of 0 in idte, means IST is NOT used\n");
    kdbxp("  ist1: %016lx  ist2: %016lx  ist3: %016lx\n",  
           tss->ist[0], tss->ist[1], tss->ist[2]);
    kdbxp("  ist4: %016lx  ist5: %016lx  ist6: %016lx\n",  
           tss->ist[3], tss->ist[4], tss->ist[5]);
    kdbxp("  ist7: %016lx\n\n", tss->ist[6]);
}

void kdb_show_special_regs(void)
{
    struct desc_ptr desc;
    unsigned short tr;                 /* Task Register segment selector */
    __u64 efer;
    struct desc_struct *gdtpage = get_current_gdt_ro();

    kdbxp("\nSpecial Registers:\n");
    __asm__ __volatile__ ("sidt  (%0) \n" :: "a"(&desc) : "memory");
    kdbxp("IDTR: addr: %016lx limit: %04x\n", desc.address, desc.size);

    /* 64bit: segementation is off, so don't display */ 
    __asm__ __volatile__ ("sgdt  (%0) \n" :: "a"(&desc) : "memory");
    kdbxp("GDTR: addr: %016lx limit: %04x", desc.address, desc.size);
    kdbxp("  cpu gdt page: %p\n", gdtpage);

    __asm__ __volatile__ ("str (%0) \n":: "a"(&tr) : "memory");
    kdbxp("TR(selector): %x  gdt index: $%d\n", tr, tr >> 3);
    kdbx_dump_tss();

    kdbxp("cr0: %016lx  cr2: %016lx\n", read_cr0(), read_cr2());
    kdbxp("cr3: %016lx  cr4: %016lx\n", kdbx_read_cr3(), __read_cr4());

    rdmsrl(MSR_EFER, efer);    /* IA32_EFER */
    kdbxp("efer:"KDBF64" LMA(IA-32e mode):%d SCE(syscall/sysret):%d\n",
         efer, ((efer&EFER_LMA) != 0), ((efer&EFER_SCE) != 0));

    kdbxp("DR0: %016lx  DR1:%016lx  DR2:%016lx\n", kdbx_rd_dbgreg(0),
         kdbx_rd_dbgreg(1), kdbx_rd_dbgreg(2)); 
    kdbxp("DR3: %016lx  DR6:%016lx  DR7:%016lx\n", kdbx_rd_dbgreg(3),
         kdbx_rd_dbgreg(6), kdbx_rd_dbgreg(7)); 
}

void kdbx_print_regs(struct pt_regs *regs)
{
    int guest_mode = kdbx_guest_mode(regs);

#ifdef __x86_64__
    kdbxp("        rip: %016lx   rsp: %016lx   rbp: %016lx\n", 
          regs->ip, regs->sp, regs->bp);
    kdbxp("      > rax: %016lx   rbx: %016lx   rcx: %016lx\n",
          regs->ax, regs->bx, regs->cx);
    kdbxp("        rdx: %016lx   rsi: %016lx   rdi: %016lx<<\n",
          regs->dx, regs->si, regs->di);
    kdbxp("         r8: %016lx    r9: %016lx   r10: %016lx\n",
          regs->r8, regs->r9, regs->r10);
    kdbxp("        r11: %016lx   r12: %016lx   r13: %016lx\n",
          regs->r11,  regs->r12, regs->r13);
    kdbxp("        r14: %016lx   r15: %016lx\n", regs->r14, regs->r15);

    /* only the above are saved in the kvm_vcpu_arch struct */
    if ( guest_mode )
        return;

    kdbxp("     eflags: %016lx  orig_ax:%016lx  cs: %04x  ss: %04x\n", 
          regs->flags, regs->orig_ax, regs->cs, regs->ss);
#else
    kdbxp("      eflags: %016lx eip: 016lx\n", regs->flags, regs->eip);
    kdbxp("      eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
         regs->eax, regs->ebx, regs->ecx, regs->edx);
    kdbxp("      esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
         regs->esi, regs->edi, regs->ebp, regs->esp);
    kdbxp("      ds: %04x   es: %04x   fs: %04x   gs: %04x   "
     "      ss: %04x   cs: %04x\n", regs->ds, regs->es, regs->fs,
         regs->gs, regs->ss, regs->cs);
    kdbxp("      errcode:%04lx entryvec:%04lx upcall_mask:%lx\n", 
         regs->error_code, regs->entry_vector, regs->saved_upcall_mask);
#endif
}

/* 
 * FUNCTION: Dispaly Registers. If "sp" argument, then display additional regs
 */
static kdbx_cpu_cmd_t kdb_usgf_dr(void)
{
    kdbxp("dr [sp]: display registers. sp to display special regs also\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_dr(int argc, const char **argv, struct pt_regs *regs)
{
    KDBGP1("regs:%p .rsp:%lx .rip:%lx\n", regs, regs->sp, regs->ip);
    /* show_regs(regs); */ /* uses printk, so output to dmesg only */

    kdbxp("[%c]current task:%p comm:%s\n", kdbx_guest_mode(regs) ? 'G' : 'H',
          current, current->comm);
    kdbx_print_regs(regs);

    if (argc > 1 && !strcmp(argv[1], "sp")) {
        /* if guest mode read from the vmcs */
        if ( kdbx_guest_mode(regs) ) {
            kdbxp("\nGuest mode: check vmcs\n");

            return KDB_CPU_MAIN_KDB;
        }
        kdb_show_special_regs();
    }
    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Modify Register
 */
static kdbx_cpu_cmd_t kdb_usgf_mr(void)
{
    kdbxp("mr reg val : Modify Register. val assumed in hex\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_mr(int argc, const char **argv, struct pt_regs *regs)
{
    const char *argp;
    int regoffs;
    ulong val;

    if (argc != 3 || !kdb_str2ulong(argv[2], &val)) {
        return kdb_usgf_mr();
    }
    argp = argv[1];

#if defined(__x86_64__)
    if ((regoffs = kdb_valid_reg(argp)) != -1)
        *((uint64_t *)((char *)regs+regoffs)) = val;
#else
    if (!strcmp(argp, "eax"))
        regs->eax = val;
    else if (!strcmp(argp, "ebx"))
        regs->ebx = val;
    else if (!strcmp(argp, "ecx"))
        regs->ecx = val;
    else if (!strcmp(argp, "edx"))
        regs->edx = val;
    else if (!strcmp(argp, "esi"))
        regs->esi = val;
    else if (!strcmp(argp, "edi"))
        regs->edi = val;
    else if (!strcmp(argp, "ebp"))
        regs->ebp = val;
    else if (!strcmp(argp, "esp"))
        regs->esp = val;
    else if (!strcmp(argp, "eflags") || !strcmp(argp, "rflags"))
        regs->eflags = val;
#endif
    else
        kdbxp("Error. Bad register : %s\n", argp);

    return KDB_CPU_MAIN_KDB;
}

static void kdbx_enable_bp_vmexit(struct kvm *kp)
{
    struct kvm_vcpu *vp;
    int i;

    for (i = 0; i < KVM_MAX_VCPUS; i++) {
        if ( (vp = kp->vcpus[i]) ) {
            vp->guest_debug |= KVM_GUESTDBG_USE_SW_BP;
        }
    }
}

static void kdbx_disable_bp_vmexit(struct kvm *kp)
{
    struct kvm_vcpu *vp;
    int i;

    for (i = 0; i < KVM_MAX_VCPUS; i++) {
        if ( (vp = kp->vcpus[i]) ) {
            vp->guest_debug &= ~KVM_GUESTDBG_USE_SW_BP;
        }
    }
}

static kdbx_cpu_cmd_t kdb_usgf_ss(void)
{
    kdbxp("ss: single step\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_ss(int argc, const char **argv, struct pt_regs *regs)
{
    #define KDB_HALT_INSTR 0xf4

    kdbbyt_t byte;
    int ccpu = smp_processor_id();
    int guest_mode = kdbx_guest_mode(regs);
    struct kvm_vcpu *vp = guest_mode ? kdbx_pid_to_vcpu(current->pid, 0) : NULL;

    KDBGP("[%d]enter kdb_cmdf_ss vp:%p tif:%d\n", ccpu, vp, tif_need_resched());
    if (!regs) {
        kdbxp("%s: regs not available\n", __FUNCTION__);
        return KDB_CPU_MAIN_KDB;
    }
    if (kdbx_read_mem(regs->KDBIP, &byte, 1, vp) == 1) {
        if (byte == KDB_HALT_INSTR) {
            kdbxp("kdb: jumping over halt instruction\n");
            regs->KDBIP++;
        }
    } else {
        kdbxp("[%d]kdb: Failed to read byte at: %lx vp:%p\n", regs->KDBIP, 
              ccpu, vp);
        return KDB_CPU_MAIN_KDB;
    }
    return KDB_CPU_SS;
}

/* FUNCTION: Next Instruction, step over the call instr to the next instr */
static kdbx_cpu_cmd_t kdb_usgf_ni(void)
{
    kdbxp("ni: single step, stepping over function calls\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_ni(int argc, const char **argv, struct pt_regs *regs)
{
    int sz, i;
    pid_t gpid = kdbx_guest_mode(regs) ? current->pid : 0;
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(gpid, 0);

    KDBGP("f_ni:gpid:%d vp:%p TIF:%d\n", gpid, vp, tif_need_resched());
    if (!regs) {
        kdbxp("%s: regs not available\n", __FUNCTION__);
        return KDB_CPU_MAIN_KDB;
    }
    if ((sz=kdbx_check_call_instr(regs->KDBIP, gpid)) == 0)  /* !call instr */
        return kdb_cmdf_ss(argc, argv, regs);         /* just do ss */

    if ( (i = kdb_set_bp(gpid,regs->KDBIP+sz,1,0,0,0,0)) >= KDBMAXSBP)/*failed*/
        return KDB_CPU_MAIN_KDB;

    kdb_sbpa[i].bp_ni = 1;
    regs->flags &= ~X86_EFLAGS_TF;      /* for vmx, cleared on every vmexit */
    if ( vp )
        kdbx_enable_bp_vmexit(vp->kvm); /* ni needs this too */

    /* 10/22/18: too many kernel threads that a cpu will offload to during ni,
     * so try using GO */
#ifdef KDBX_CONFIG_NI_AS_NOT_GO
    kdb_install_swbp(i);
    return KDB_CPU_NI;
#endif
    return KDB_CPU_GO;
}

static void kdb_btf_enable(void)
{
    u64 debugctl;

    rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
    wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl | 0x2);
}

/* Single Step to branch. Doesn't seem to work very well */
static kdbx_cpu_cmd_t kdb_usgf_ssb(void)
{
    kdbxp("ssb: singe step to branch\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_ssb(int argc, const char **argv, struct pt_regs *regs)
{
    KDBGP("kdb: enter kdb_cmdf_ssb. TIF:%d\n", tif_need_resched());
    if (!regs) {
        kdbxp("%s: regs not available\n", __FUNCTION__);
        return KDB_CPU_MAIN_KDB;
    }
    regs->flags |= X86_EFLAGS_TF;
    kdb_btf_enable();
    return KDB_CPU_SS;
}

/* 
 * FUNCTION: Continue Execution. TF must be cleared here as this could run on 
 *           any cpu. Hence not OK to do it from kdb_end_session.
 */
static kdbx_cpu_cmd_t kdb_usgf_go(void)
{
    kdbxp("go: leave kdb and continue execution\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_go(int argc, const char **argv, struct pt_regs *regs)
{
    regs->flags &= ~X86_EFLAGS_TF;      /* for vmx, cleared on every vmexit */
    return KDB_CPU_GO;
}

/* All cpus must display their current context */
static kdbx_cpu_cmd_t kdb_cpu_status_all(int ccpu, struct pt_regs *regs)
{
    int cpu;

    for_each_online_cpu(cpu) {
        if (cpu == ccpu) {
            kdbxp("[%d]", ccpu);
            kdbx_display_pc(regs);
        } else {
            if (kdbx_cpu_cmd[cpu] != KDB_CPU_PAUSE)   /* hung cpu */
                continue;
            kdbx_cpu_cmd[cpu] = KDB_CPU_SHOWPC;
            while (kdbx_cpu_cmd[cpu]==KDB_CPU_SHOWPC);
        }
    }
    return KDB_CPU_MAIN_KDB;
}

/* 
 * display/switch CPU. 
 *  Argument:
 *     none:   just go back to initial cpu
 *     cpunum: switch to given vpu
 *     "all":  show one line status of all cpus
 */
extern volatile int kdb_init_cpu;
static kdbx_cpu_cmd_t kdb_usgf_cpu(void)
{
    kdbxp("cpu [all|num]: none will switch back to initial cpu\n");
    kdbxp("               cpunum to switch to the vcpu. all to show status\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_cpu(int argc, const char **argv, struct pt_regs *regs)
{
    int cpu;
    int ccpu = smp_processor_id();

    if (argc > 1) {
        if (!strcmp(argv[1], "all"))
            return kdb_cpu_status_all(ccpu, regs);

        cpu = (int)simple_strtoul(argv[1], NULL, 0); /* handles 0x */
        if (cpu >= 0 && cpu < NR_CPUS && cpu != ccpu && 
            cpu_online(cpu) && kdbx_cpu_cmd[cpu] == KDB_CPU_PAUSE)
        {
            kdbxp("Switching to cpu:%d\n", cpu);
            kdbx_cpu_cmd[cpu] = KDB_CPU_MAIN_KDB;

            /* clear any single step on the current cpu */
            regs->flags &= ~X86_EFLAGS_TF; /* vmx clears on vmexit */
            return KDB_CPU_PAUSE;
        } else {
            if (cpu != ccpu)
                kdbxp("Unable to switch to cpu:%d\n", cpu);
            else {
                kdbx_display_pc(regs);
            }
            return KDB_CPU_MAIN_KDB;
        }
    }
    /* no arg means back to initial cpu */
    if (!kdbx_sys_crash && ccpu != kdb_init_cpu) {
        if (kdbx_cpu_cmd[kdb_init_cpu] == KDB_CPU_PAUSE) {
            regs->flags &= ~X86_EFLAGS_TF;
            kdbx_cpu_cmd[kdb_init_cpu] = KDB_CPU_MAIN_KDB;
            return KDB_CPU_PAUSE;
        } else
            kdbxp("Unable to switch to: %d\n", kdb_init_cpu);
    }
    return KDB_CPU_MAIN_KDB;
}

/* send NMI to all or given CPU. Must be crashed/fatal state */
static kdbx_cpu_cmd_t kdb_usgf_nmi(void)
{
    kdbxp("nmi cpu#|all: send nmi to cpu/s. must reboot when done with kdb\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_nmi(int argc, const char **argv, struct pt_regs *regs)
{
    struct cpumask cpumask;
    int ccpu = smp_processor_id();

    if (argc != 2)
        return kdb_usgf_nmi();

#if 0
    if (!kdbx_sys_crash) {
        kdbxp("kdb: nmi cmd available in crashed state only\n");
        return KDB_CPU_MAIN_KDB;
    }
#endif
    if (!strcmp(argv[1], "all"))
        cpumask = *cpu_online_mask;
    else {
        int cpu = (int)simple_strtoul(argv[1], NULL, 0);

        if (cpu >= 0 && cpu < NR_CPUS && cpu != ccpu && cpu_online(cpu))
            cpumask = *cpumask_of(cpu);
        else {
            kdbxp("KDB nmi: invalid cpu %s\n", argv[1]);
            return KDB_CPU_MAIN_KDB;
        }
    }
    kdbx_nmi_pause_cpus(cpumask);  /* will remove itself */
    return KDB_CPU_MAIN_KDB;
}

static int kdb_prnt_pcpu_offs(void)
{
    int cpu;

    kdbxp("Per cpu offsets:\n");
    for_each_cpu(cpu, cpu_online_mask)
        kdbxp("    cpu:%d  offset:"KDBFL"\n", cpu, per_cpu_offset(cpu));

    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_pcpu(void)
{
    kdbxp("pcpu [cpunum|\"offs\"]: display per cpu vars for the cpu\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_pcpu(int argc, const char **argv, struct pt_regs *regs)
{
    ulong irq_sp_end;
    struct tss_struct *tss;
    int i, cpu = smp_processor_id();

    if ( argc == 2 ) {
        if (!strcmp(argv[1], "offs"))
            return kdb_prnt_pcpu_offs();
    
        if ( !kdb_str2cpu(argv[1], &cpu, 1) )
            return KDB_CPU_MAIN_KDB;
    }
    kdbxp("cpu vars for cpu:%d\n", cpu);

    irq_sp_end = (ulong)per_cpu(irq_stack_ptr, cpu);
    kdbxp("irq_stack: "KDBFL"  irq_stack_end: "KDBFL"\n",
          irq_sp_end - IRQ_STACK_SIZE, irq_sp_end);

    kdbxp("entry_stack: %p\n", cpu_entry_stack(cpu));
    kdbxp("cpu_current_top_of_stack: %p\n", 
          per_cpu(cpu_current_top_of_stack, cpu));
    tss =  &per_cpu(cpu_tss_rw, cpu);
    kdbxp("tss_struct at: %p\n", tss);

    kdbxp("Exception stacks at %p\n",get_cpu_entry_area(cpu)->exception_stacks);
    for (i = 0; i < N_EXCEPTION_STACKS; i++) {
        kdbxp("    %s of size %d at %lx\n",
              stack_type_name(STACK_TYPE_EXCEPTION+i),
              i == DEBUG_STACK-1 ? DEBUG_STKSZ : EXCEPTION_STKSZ,
              tss->x86_tss.ist[i]);
    }
    return KDB_CPU_MAIN_KDB;
}

/* ========================= Breakpoints ==================================== */
static void kdb_prnt_bp_cond(int bpnum)
{
    struct kdb_bpcond *bpcp = &kdb_sbpa[bpnum].u.bp_cond;

    if (bpcp->bp_cond_status == 1) {
        kdbxp("     ( %s %c%c %lx )\n", 
             kdb_regoffs_to_name(bpcp->bp_cond_lhs),
             bpcp->bp_cond_type == 1 ? '=' : '!', '=', bpcp->bp_cond_rhs);
    } else {
        kdbxp("     ( %lx %c%c %lx )\n", bpcp->bp_cond_lhs,
             bpcp->bp_cond_type == 1 ? '=' : '!', '=', bpcp->bp_cond_rhs);
    }
}

static void kdb_prnt_bp_extra(int bpnum)
{
    if (kdb_sbpa[bpnum].bp_type == 2) {
        ulong i, arg, *btp = kdb_sbpa[bpnum].u.bp_btp;
        
        kdbxp("   will trace ");
        for (i=0; i < KDB_MAXBTP && btp[i]; i++)
            if ((arg=btp[i]) < sizeof (struct pt_regs)) {
                kdbxp(" %s ", kdb_regoffs_to_name(arg));
            } else {
                kdbxp(" %lx ", arg);
            }
        kdbxp("\n");

    } else if (kdb_sbpa[bpnum].bp_type == 1)
        kdb_prnt_bp_cond(bpnum);
}

/*
 * List software breakpoints
 */
static kdbx_cpu_cmd_t kdb_display_sbkpts(void)
{
    int i;

    for(i = 0; i < KDBMAXSBP; i++) {
        if (kdb_sbpa[i].bp_addr && !kdb_sbpa[i].bp_deleted) {
            pid_t pid = kdb_sbpa[i].bp_pid;
            pid_t gpid = kdbx_pid_to_vcpu(pid, 0) ? pid : 0;

            kdbxp("[%d]: pid:%d 0x%lx   ", i, pid, kdb_sbpa[i].bp_addr);
            kdbx_prnt_addr2sym(gpid, kdb_sbpa[i].bp_addr, "\n");
            kdb_prnt_bp_extra(i);
        }
    }
    return KDB_CPU_MAIN_KDB;
}

/*
 * Check if any breakpoints that we need to install (delayed install)
 * Returns: 1 if yes, 0 if none.
 */
int kdbx_swbp_exists(void)
{
    int i;

    for (i=0; i < KDBMAXSBP; i++)
        if (kdb_sbpa[i].bp_addr && !kdb_sbpa[i].bp_deleted)
            return 1;
    return 0;
}

#if 0
/*
 * Check if any breakpoints were deleted this kdb session
 * Returns: 0 if none, 1 if yes
 */
static int kdb_swbp_deleted(void)
{
    int i;

    for (i=0; i < KDBMAXSBP; i++)
        if (kdb_sbpa[i].bp_addr && kdb_sbpa[i].bp_deleted)
            return 1;
    return 0;
}
#endif

/*
 * Flush deleted sw breakpoints
 */
void kdbx_flush_swbp_table(void)
{
#if 0
    int i;

    KDBGP("[%d] flush_swbp_table: deleted:%x\n", smp_processor_id(), 
          kdb_swbp_deleted());
    for(i=0; i < KDBMAXSBP; i++)
        if (kdb_sbpa[i].bp_addr && kdb_sbpa[i].bp_deleted) {
            KDBGP("flush:[%x] addr:0x%lx\n", i, kdb_sbpa[i].bp_addr);

            memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
        }
#endif
}

/*
 * Delete/Clear a sw breakpoint
 */
static kdbx_cpu_cmd_t kdb_usgf_bc(void)
{
    kdbxp("bc $num|all : clear given or all breakpoints\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_bc(int argc, const char **argv, struct pt_regs *regs)
{
    int i, bpnum = -1, delall = 0;
    const char *argp;

    if (argc != 2)
        return kdb_usgf_bc();

    if (!kdbx_swbp_exists()) {
        kdbxp("No breakpoints are set\n");
        return KDB_CPU_MAIN_KDB;
    }
    argp = argv[1];

    if (!strcmp(argp, "all"))
        delall = 1;
    else if (!kdb_str2deci(argp, &bpnum) || bpnum < 0 || bpnum > KDBMAXSBP) {
        kdbxp("Invalid bpnum: %s\n", argp);
        return KDB_CPU_MAIN_KDB;
    }
    for (i=0; i < KDBMAXSBP; i++) {
        if (delall && kdb_sbpa[i].bp_addr) {
            if ( kdb_sbpa[i].bp_deleted )
                continue;

            if (kdb_sbpa[i].bp_pid != -1)
                kdbxp("Deleted breakpoint [%x] at 0x%lx pid:%d\n", 
                      i, kdb_sbpa[i].bp_addr, kdb_sbpa[i].bp_pid);
            else 
                kdbxp("Deleted breakpoint [%x] at 0x%lx\n", 
                      i, kdb_sbpa[i].bp_addr);

            if (kdb_sbpa[i].bp_just_added)
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
            else
                kdb_sbpa[i].bp_deleted = 1;
            continue;
        }
        if (bpnum != -1 && bpnum == i) {
            if (kdb_sbpa[i].bp_pid != -1)
                kdbxp("Deleted breakpoint [%x] at 0x%lx pid:%d\n", 
                      i, kdb_sbpa[i].bp_addr, kdb_sbpa[i].bp_pid);
            else
                kdbxp("Deleted breakpoint [%x] at 0x%lx\n", 
                      i, kdb_sbpa[i].bp_addr);

            if (kdb_sbpa[i].bp_just_added)
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
            else
                kdb_sbpa[i].bp_deleted = 1;
            break;
        }
    }
    if (i >= KDBMAXSBP && !delall)
        kdbxp("Unable to delete breakpoint: %s\n", argp);

    return KDB_CPU_MAIN_KDB;
}

/*
 * Install a breakpoint in the given array entry
 * Returns: 0 : failed to install
 *          1 : installed successfully
 */
static int kdb_install_swbp(int idx)         /* which entry in the bp array */
{
    kdbva_t addr = kdb_sbpa[idx].bp_addr;
    kdbbyt_t *p = &kdb_sbpa[idx].bp_originst;
    pid_t pid = kdb_sbpa[idx].bp_pid;
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(pid, 0);

    if ( kdb_sbpa[idx].bp_deleted ) {
        kdbxp("[%d]Trying to install deleted bp:%d\n", smp_processor_id(), idx);
        return 0;
    }
    if (kdbx_read_mem(addr, p, KDBBPSZ, vp) != KDBBPSZ) {
        kdbxp("Failed(R) to install bp:%x at:0x%lx pid:%d. Deleted.\n",
              idx, kdb_sbpa[idx].bp_addr, kdb_sbpa[idx].bp_pid);
        kdb_sbpa[idx].bp_deleted = 1;
        // memset(&kdb_sbpa[idx], 0, sizeof(kdb_sbpa[idx]));
        return 0;
    }
    KDBGP1("install swbp: addr:%lx orig:%x sz:%d\n", addr, *p, KDBBPSZ);

    if (kdbx_write_mem(addr, &kdb_bpinst, KDBBPSZ, vp) != KDBBPSZ) {
        kdbxp("Failed(W) to install bp:%x at:0x%lx pid:%d. Deleted\n",
              idx, kdb_sbpa[idx].bp_addr, kdb_sbpa[idx].bp_pid);
        kdb_sbpa[idx].bp_deleted = 1;
        // memset(&kdb_sbpa[idx], 0, sizeof(kdb_sbpa[idx]));
        return 0;
    }
    if ( vp )
        kdbx_enable_bp_vmexit(vp->kvm);     /* ni needs this too */

    KDBGP("[%d]install_swbp:[%x] %lx ni:%d orig:%x pid:%d vp:%p\n",
          smp_processor_id(), idx, kdb_sbpa[idx].bp_addr, kdb_sbpa[idx].bp_ni,
          kdb_sbpa[idx].bp_originst, pid, vp);

    return 1;
}

/*
 * Install all the software breakpoints
 */
void kdbx_install_all_swbp(void)
{
    int i;
    for(i=0; i < KDBMAXSBP; i++)
        if (!kdb_sbpa[i].bp_deleted && kdb_sbpa[i].bp_addr)
            kdb_install_swbp(i);
}

static void kdb_uninstall_a_swbp(int i)
{
    kdbva_t addr = kdb_sbpa[i].bp_addr;
    kdbbyt_t originst = kdb_sbpa[i].bp_originst;
    pid_t pid = kdb_sbpa[i].bp_pid;
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(pid, 0);
    int ccpu = smp_processor_id();

    kdb_sbpa[i].bp_just_added = 0;
    if (!addr)
        return;

    if (kdbx_write_mem(addr, &originst, KDBBPSZ, vp) != KDBBPSZ) {
        kdbxp("Failed to uninstall breakpoint %x at:0x%lx pid:%d\n",
             i, kdb_sbpa[i].bp_addr, pid);
    }
    KDBGP("[%d] uninstalled bp:%lx ni:%d\n", ccpu, addr, kdb_sbpa[i].bp_ni);

    /* this called for ni also */
    if ( vp )
        kdbx_disable_bp_vmexit(vp->kvm);
}

/* Uninstall all the software breakpoints at beginning of kdb session */
void kdbx_uninstall_all_swbp(void)
{
    int i;

    for(i=0; i < KDBMAXSBP; i++) 
        kdb_uninstall_a_swbp(i);
}

/* RETURNS: rc == 2: condition was not met,  rc == 3: condition was met */
static int kdb_check_bp_condition(int bpnum, struct pt_regs *regs)
{
    ulong res = 0, lhsval=0;
    struct kdb_bpcond *bpcp = &kdb_sbpa[bpnum].u.bp_cond;
    pid_t gpid = kdb_sbpa[bpnum].bp_pid;
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(gpid, 0);

    if (bpcp->bp_cond_status == 1) {             /* register condition */
        uint64_t *rp = (uint64_t *)((char *)regs + bpcp->bp_cond_lhs);
        lhsval = *rp;
    } else if (bpcp->bp_cond_status == 2) {      /* memaddr condition */
        ulong addr = bpcp->bp_cond_lhs;
        int num = sizeof(lhsval);

        if (kdbx_read_mem(addr, (kdbbyt_t *)&lhsval, num, vp) != num) {
            kdbxp("kdb: unable to read %d bytes at %lx\n", num, addr);
            return 3;
        }
    }
    if (bpcp->bp_cond_type == 1)                 /* lhs == rhs */
        res = (lhsval == bpcp->bp_cond_rhs);
    else                                         /* lhs != rhs */
        res = (lhsval != bpcp->bp_cond_rhs);

    if (!res)
        kdbxp("KDB: [%d]Ignoring bp:%d condition not met. val:%lx\n", 
              smp_processor_id(), bpnum, lhsval); 

    KDBGP1("bpnum:%d cond: %d %d %lx %lx res:%d\n", bpnum, 
           bpcp->bp_cond_status, bpcp->bp_cond_type, bpcp->bp_cond_lhs, 
           bpcp->bp_cond_rhs, res);

    return (res ? 3 : 2);
}

static void kdb_prnt_btp_info(int bpnum, struct pt_regs *regs)
{
    ulong i, arg, val, num, *btp = kdb_sbpa[bpnum].u.bp_btp;
    pid_t gpid = kdb_sbpa[bpnum].bp_pid;
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(gpid, 1);

    kdbx_prnt_addr2sym(gpid, regs->KDBIP, "\n");
    num = sizeof(ulong);
    for (i=0; i < KDB_MAXBTP && (arg=btp[i]); i++) {
        if (arg < sizeof (struct pt_regs)) {
            uint64_t *rp = (uint64_t *)((char *)regs + arg);
            kdbxp(" %s: %016lx ", kdb_regoffs_to_name(arg), *rp);
        } else {
            if (kdbx_read_mem(arg, (kdbbyt_t *)&val, num, vp) != num)
                kdbxp("kdb: unable to read %d bytes at %lx\n", num, arg);
            if (num == 8)
                kdbxp(" %016lx:%016lx ", arg, val);
            else
                kdbxp(" %08lx:%08lx ", arg, val);
        }
    }
    kdbxp("\n");
    KDBGP1("bpnum:%d cpid:%d btp:%p num:%d\n", bpnum, current->pid, btp, num);
}

/* match all threads in a pid */
static int kdb_bp_pid_match(pid_t bp_pid)
{
    pid_t cpid = current->pid;

    if ( cpid == bp_pid || kdbx_pid2tgid(cpid) == kdbx_pid2tgid(bp_pid) ) {
        return 1;
    }

kdbxp("[%d]BP PID doesn't match..bp_pid:%d cur:%d\n",smp_processor_id(),  
      bp_pid, cpid);
    return 0;
}

/* vmx doesn't increase the IP by 1 on bp. Check and *change* here */
static int kdb_bp_addr_match(struct pt_regs *regs, ulong bp_addr)
{
    if ( kdbx_guest_mode(regs) )
        return bp_addr == regs->KDBIP;

    /* host mode */
    if ( bp_addr == regs->KDBIP - KDBBPSZ ) {
        regs->KDBIP -= KDBBPSZ;
        return 1;
    }
    return 0;
}

/*
 * Check if the BP trap belongs to us. 
 * Return: 0 : not one of ours. IP not changed. (leave kdb)
 *         1 : one of ours but deleted. IP decremented. (leave kdb)
 *         2 : one of ours but condition not met, or btp. IP decremented.(leave)
 *         3 : one of ours and active. IP decremented. (stay in kdb)
 */
int kdbx_check_sw_bkpts(struct pt_regs *regs)
{
    int i, rc = 0;
    int ccpu = smp_processor_id();

    for(i = 0; i < KDBMAXSBP; i++) {
        pid_t bp_pid = kdb_sbpa[i].bp_pid;
        struct kvm_vcpu *vp = bp_pid ? kdbx_pid_to_vcpu(bp_pid, 0) : NULL;

        /* if the user process or the guest is gone... let it go! */
        if ( bp_pid && vp == NULL ) {
            if ( kdb_pid2tp(bp_pid, 0) == 0 ) {
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
                continue;
            }
        }
        if ( kdb_bp_addr_match(regs, kdb_sbpa[i].bp_addr) ) 
        {
            /* one of ours. If bp for a pid, check if current matches */
            if ( (bp_pid && !kdb_bp_pid_match(bp_pid)) ) {
                rc = 2;
                break;
            }
            rc = 3;

            if (kdb_sbpa[i].bp_ni) {
                kdb_uninstall_a_swbp(i);
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
            } else if (kdb_sbpa[i].bp_deleted) {
                rc = 1;
            } else if (kdb_sbpa[i].bp_type == 1) {
                rc = kdb_check_bp_condition(i, regs);
            } else if (kdb_sbpa[i].bp_type == 2) {
                kdb_prnt_btp_info(i, regs);
                rc = 2;
            }
            break;
        }
    }
    if ( rc == 3 && kdb_sbpa[i].bp_addr ) /* make sure was not an ni */
        kdbxp("Breakpoint on cpu %d at 0x%lx\n", ccpu, regs->KDBIP);

    KDBGP("[%d] rc:%d cpid:%d addr:%lx\n", 
           smp_processor_id(), rc, current->pid, kdb_sbpa[i].bp_addr);
    return (rc);
}

/* Eg: r6 == 0x123EDF  or 0xFFFF2034 != 0xDEADBEEF
 * regoffs: -1 means lhs is not reg. else offset of reg in pt_regs
 * addr: memory location if lhs is not register, eg, 0xFFFF2034
 * condp : points to != or ==
 * rhsval : right hand side value
 */
static void kdb_set_bp_cond(int bpnum, int regoffs, ulong addr, 
                            char *condp, ulong rhsval)
{
    if (bpnum >= KDBMAXSBP) {
        kdbxp("BUG: %s got invalid bpnum\n", __FUNCTION__);
        return;
    }
    if (regoffs != -1) {
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_status = 1;
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_lhs = regoffs;
    } else if (addr != 0) {
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_status = 2;
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_lhs = addr;
    } else {
        kdbxp("error: invalid call to kdb_set_bp_cond\n");
        return;
    }
    kdb_sbpa[bpnum].u.bp_cond.bp_cond_rhs = rhsval;

    if (*condp == '!')
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_type = 2;
    else
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_type = 1;
}

/* install breakpt at given addr. 
 * pid: 0 ==> entire host.. else, either host pid or guest pid.
 * ni: bp for next instr 
 * btpa: ptr to args for btp for printing when bp is hit
 * lhsp/condp/rhsp: point to strings of condition
 *
 * RETURNS: the index in array where installed. KDBMAXSBP if error 
 */
static int kdb_set_bp(pid_t pid, kdbva_t addr, int ni, ulong *btpa, char *lhsp,
                      char *condp, char *rhsp)
{
    int i, pre_existing = 0, regoffs = -1;
    ulong memloc=0, rhsval=0, tmpul;
    struct kvm_vcpu *vp = pid ? kdbx_pid_to_vcpu(pid, 1) : NULL;
    int gpid = vp ? pid : 0;

    if ( pid && vp == NULL )
        return KDBMAXSBP;
        
    if ( btpa && (lhsp || rhsp || condp) ) {
        kdbxp("internal error. btpa and (lhsp || rhsp || condp) set\n");
        return KDBMAXSBP;
    }
    if ( lhsp && ((regoffs=kdb_valid_reg(lhsp)) == -1)  &&
         kdb_str2ulong(lhsp, &memloc) &&
         kdbx_read_mem(memloc, (kdbbyt_t *)&tmpul, sizeof(tmpul), vp) == 0) {

        kdbxp("error: invalid argument: %s\n", lhsp);
        return KDBMAXSBP;
    }
    if (rhsp && ! kdb_str2ulong(rhsp, &rhsval)) {
        kdbxp("error: invalid argument: %s\n", rhsp);
        return KDBMAXSBP;
    }

    /* see if bp already set */
    for (i=0; i < KDBMAXSBP; i++) {
        pid_t bp_addr = kdb_sbpa[i].bp_addr;
        pid_t bp_pid = kdb_sbpa[i].bp_pid;

        if ( bp_addr == addr && kdbx_pid2tgid(bp_pid) == kdbx_pid2tgid(pid) ) {
            if (kdb_sbpa[i].bp_deleted) {
                /* just re-set this bp again */
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
                pre_existing = 1;
            } else {
                kdbxp("Breakpoint already set \n");
                return KDBMAXSBP;
            }
        }
    }
    /* see if any room left for another breakpoint */
    for (i=0; i < KDBMAXSBP; i++)
        if (!kdb_sbpa[i].bp_addr)
            break;
    if (i >= KDBMAXSBP) {
        kdbxp("ERROR: Breakpoint table full....\n");
        return i;
    }
    kdb_sbpa[i].bp_addr = addr;
    kdb_sbpa[i].bp_pid = pid;
    if (btpa) {
        kdb_sbpa[i].bp_type = 2;
        kdb_sbpa[i].u.bp_btp = btpa;
    } else if (regoffs != -1 || memloc) {
        kdb_sbpa[i].bp_type = 1;
        kdb_set_bp_cond(i, regoffs, memloc, condp, rhsval);
    } else
        kdb_sbpa[i].bp_type = 0;

    if (kdb_install_swbp(i)) {                  /* make sure it can be done */

        kdb_uninstall_a_swbp(i);                /* dont' show user INT3 */
        if (ni)
            return i;
#if 0
        if (!pre_existing)               /* make sure no is cpu sitting on it */
            kdb_sbpa[i].bp_just_added = 1;
#endif
        if ( pid )
            kdbxp("bp %d set for %s:%d at: 0x%lx ", i, vp ? "vm" : "pid",
                  kdb_sbpa[i].bp_pid, kdb_sbpa[i].bp_addr);
        else 
            kdbxp("bp %d set at: 0x%lx ", i, kdb_sbpa[i].bp_addr);
        kdbx_prnt_addr2sym(gpid, addr, "\n");
        kdb_prnt_bp_extra(i);

    } else {
        kdbxp("ERROR:Can't install bp: 0x%lx pid:%d\n", addr, pid);
        if (pre_existing)     /* in case a cpu is sitting on this bp in traps */
            kdb_sbpa[i].bp_deleted = 1;
        else
            memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));

        return KDBMAXSBP;
    }

    return i;
}

/* Set/List Software Breakpoint/s */
static kdbx_cpu_cmd_t kdb_usgf_bp(void)
{
    kdbxp("bp [addr|sym][pid][condition]: display or set a breakpoint\n");
    kdbxp("  where cond is like: r6 == 0x123F or rax != DEADBEEF or \n");
    kdbxp("       ffff82c48038fe58 == 321E or 0xffff82c48038fe58 != 0\n");
    kdbxp("  regs: rax rbx rcx rdx rsi rdi rbp rsp r8 r9");
    kdbxp(" r10 r11 r12 r13 r14 r15 rflags\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_bp(int argc, const char **argv, struct pt_regs *regs)
{
    kdbva_t addr;
    int idx = -1;
    pid_t gpid, pid = 0;
    char *pidstrp, *lhsp=NULL, *condp=NULL, *rhsp=NULL;

    if (argc == 4 || argc > 6)
        return kdb_usgf_bp();

    if (argc < 2 || kdbx_sys_crash)         /* list all set breakpoints */
        return kdb_display_sbkpts();

    /* valid argc either: 2 3 5 or 6 
     * 'bp idle_loop r6 == 0xc000' OR 'bp idle_loop 3 r9 != 0xdeadbeef' */
    idx = (argc == 5) ? 2 : ((argc == 6) ? 3 : idx);
    if (argc >= 5 ) {
        lhsp = (char *)argv[idx];
        condp = (char *)argv[idx+1];
        rhsp = (char *)argv[idx+2];

        if (!kdb_str2ulong(rhsp, NULL) || *(condp+1) != '=' || 
            (*condp != '=' && *condp != '!')) {

            return kdb_usgf_bp();
        }
    }

    pidstrp = (argc == 3 || argc == 6 ) ? (char *)argv[2] : NULL;
    if (pidstrp && !kdb_str2pid(pidstrp, &pid, 1)) {
        return kdb_usgf_bp();
    }

    gpid = kdbx_pid_to_vcpu(pid, 0) ? pid : 0;

    if (!kdb_str2addr(argv[1], &addr, gpid) || addr == 0) {
        kdbxp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }

    /* if host pid, make sure addr is in the kernel text */
    if ( gpid == 0 && !kdbx_text_addr(addr, 0) ) {
        kdbxp("addr:%lx not in  host kernel text\n", addr);
        return KDB_CPU_MAIN_KDB;
    }

    kdb_set_bp(pid, addr, 0, NULL, lhsp, condp, rhsp);  /* 0 is ni flag */

    return KDB_CPU_MAIN_KDB;
}

/* trace breakpoint, meaning, upon bp trace/print some info and continue */
static kdbx_cpu_cmd_t kdb_usgf_btp(void)
{
    kdbxp("btp addr|sym [pid] reg|mem-addr... :  breakpoint trace\n");
    kdbxp("  regs: rax rbx rcx rdx rsi rdi rbp rsp r8 r9 ");
    kdbxp("r10 r11 r12 r13 r14 r15 rflags\n");
    kdbxp("  Eg. btp idle_cpu 7 rax rbx 0x20ef5a5 r9\n");
    kdbxp("      will print rax, rbx, *(long *)0x20ef5a5, r9 and continue\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_btp(int argc, const char **argv, struct pt_regs *regs)
{
    int i, btpidx, numrd, argsidx, regoffs = -1;
    kdbva_t addr, memloc=0;
    pid_t gpid = 0, pid = -1;
    ulong *btpa, tmpul;
    struct kvm_vcpu *vp;

    if (argc < 3)
        return kdb_usgf_btp();

    argsidx = 2;                   /* assume 3rd arg is pid */
    if (argc >= 3 && kdb_str2pid(argv[2], &pid, 0)) {
        argsidx = 3;               /* 3rd arg is a pid */
    }
    if ( pid == -1 )
        pid = current->pid;

    gpid = (vp = kdbx_pid_to_vcpu(pid, 0)) ? pid : 0;

    if ( !kdb_str2addr(argv[1], &addr, gpid) || addr == 0 ) {
        kdbxp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }

    /* make sure addr is in kernel text */
    if ( !kdbx_text_addr(addr, gpid) ) {
        kdbxp("addr:%lx not in kernel text\n", addr);
        return KDB_CPU_MAIN_KDB;
    }

    numrd = sizeof(unsigned long);
    if (kdbx_read_mem(addr, (kdbbyt_t *)&tmpul, numrd, vp) != numrd) {
        kdbxp("Unable to read mem from %s (%lx)\n", argv[1], addr);
        return KDB_CPU_MAIN_KDB;
    }

    for (btpidx=0; btpidx < KDBMAXSBP && kdb_btp_ap[btpidx]; btpidx++);
    if (btpidx >= KDBMAXSBP) {
        kdbxp("error: table full. delete few breakpoints\n");
        return KDB_CPU_MAIN_KDB;
    }
    btpa = kdb_btp_argsa[btpidx];
    memset(btpa, 0, sizeof(kdb_btp_argsa[0]));

    for (i=0; argv[argsidx]; i++, argsidx++) {

        if (((regoffs=kdb_valid_reg(argv[argsidx])) == -1)  &&
            kdb_str2ulong(argv[argsidx], &memloc) &&
            (memloc < sizeof (struct pt_regs) ||
            kdbx_read_mem(memloc, (kdbbyt_t *)&tmpul, sizeof(tmpul), vp) == 0)){

            kdbxp("error: invalid argument: %s\n", argv[argsidx]);
            return KDB_CPU_MAIN_KDB;
        }
        if (i >= KDB_MAXBTP) {
            kdbxp("error: cannot specify more than %d args\n", KDB_MAXBTP);
            return KDB_CPU_MAIN_KDB;
        }
        btpa[i] = (regoffs == -1) ? memloc : regoffs;
    }

    i = kdb_set_bp(gpid, addr, 0, btpa, 0, 0, 0);     /* 0 is ni flag */
    if (i < KDBMAXSBP)
        kdb_btp_ap[btpidx] = kdb_btp_argsa[btpidx];

    return KDB_CPU_MAIN_KDB;
}

/* 
 * Set/List watchpoints, ie, hardware breakpoint/s, in hypervisor
 *   Usage: wp [sym|addr] [w|i]   w == write only data watchpoint
 *                                i == IO watchpoint (read/write)
 *
 *   Eg:  wp        : list all watchpoints set
 *        wp addr   : set a read/write wp at given addr
 *        wp addr w : set a write only wp at given addr
 *        wp addr i : set an IO wp at given addr (16bits port #)
 *
 *  TBD: allow to be set on particular cpu
 */
static kdbx_cpu_cmd_t kdb_usgf_wp(void)
{
    kdbxp("wp [addr|sym][w|i]: display or set watchpoint. writeonly or IO\n");
    kdbxp("\tnote: watchpoint is triggered after the instruction executes\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_wp(int argc, const char **argv, struct pt_regs *regs)
{
    kdbva_t addr;
    int rw = 3, len = 4;       /* for now just default to 4 bytes len */

    if (argc <= 1 || kdbx_sys_crash) {       /* list all set watchpoints */
        kdbx_do_watchpoints(0, 0, 0);
        return KDB_CPU_MAIN_KDB;
    }
    if (!kdb_str2addr(argv[1], &addr, 0) || addr == 0) {
        kdbxp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    if (argc > 2) {
        if (!strcmp(argv[2], "w"))
            rw = 1;
        else if (!strcmp(argv[2], "i"))
            rw = 2;
        else {
            return kdb_usgf_wp();
        }
    }
    kdbx_do_watchpoints(addr, rw, len);
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_wc(void)
{
    kdbxp("wc $num|all : clear given or all watchpoints\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_wc(int argc, const char **argv, struct pt_regs *regs)
{
    const char *argp;
    int wpnum;              /* wp num to delete. -1 for all */

    if (argc != 2) 
        return kdb_usgf_wc();

    argp = argv[1];

    if (!strcmp(argp, "all"))
        wpnum = -1;
    else if (!kdb_str2deci(argp, &wpnum)) {
        kdbxp("Invalid wpnum: %s\n", argp);
        return KDB_CPU_MAIN_KDB;
    }
    kdbx_clear_wps(wpnum);
    return KDB_CPU_MAIN_KDB;
}

/* Dump timer/timers queues */
static kdbx_cpu_cmd_t kdb_usgf_trq(void)
{
    kdbxp("trq: dump timer queues on all cpus\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_trq(int argc, const char **argv, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,1,12)
    kdbxp("Not implemented\n");
#else
    kdbx_dump_timer_queues();
#endif
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_apic(void)
{
    kdbxp("apic: dump struct apic\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_apic(int argc, const char **argv, struct pt_regs *regs)
{
    kdbxp("struct apic: %p  name: %s\n", apic, apic->name);
    kdbxp(" get_apic_id: %s  set_apic_id: %s\n",
          kdbx_hostsym(apic->get_apic_id), kdbx_hostsym(apic->set_apic_id));
    kdbxp(" target_cpus: %s", kdbx_hostsym(apic->target_cpus));
    kdbx_prnt_cpumask((struct cpumask *)apic->target_cpus(), "\n");
    kdbxp(" dest_ mode: %d(1 log, 0 phys)  logical:0x%x\n",
          apic->irq_dest_mode, apic->dest_logical);
    kdbxp(" apicid_to_cpu_present: %s  cpu_mask_to_apicid: %s\n",
          kdbx_hostsym(apic->apicid_to_cpu_present),
          kdbx_hostsym(apic->cpu_mask_to_apicid));
    kdbxp(" cpu_present_to_apicid: %s\n", 
          kdbx_hostsym(apic->cpu_present_to_apicid));
    kdbxp(" check_phys_apicid_present: %s\n",
          kdbx_hostsym(apic->check_phys_apicid_present));

    return KDB_CPU_MAIN_KDB;
}

/* irq_desc.handle_irq: is handle_level_irq, handle_edge_irq, 
 *                      handle_fasteoi_irq, .. 
 * irq_desc.name: edge or fasteoi, etc.. 
 *
 * desc.handl_irq == handle_edge_irq / handle_fasteoi_irq / 
 *     handle_fasteoi_irq/ ... but they all call handle_irq_event_percpu 
 *     which calls desc->action->handler
 *
 * Note: irq_cfg will give vector for an irq
 */
static void kdbx_disp_irqs(int cpu)
{
    int irq;

    kdbxp("CPU %d: (name as in /proc/interrupts)\n", cpu);
    kdbxp("cpu bitmap same as /proc/irq/xx/effective_affinity\n");
    kdbxp("irq idt# cpu-bitmap desc handler(name)\n");

    for ( irq = 0; irq  < nr_irqs; irq++ ) {    /* for_each_active_irq(irq) */
        struct irq_desc *desc = irq_to_desc(irq);
        struct irqaction *ap = desc ? desc->action : NULL;
        struct irq_cfg *cfg = irq_cfg(irq);

        if ( desc == VECTOR_UNUSED || ap == NULL )  /* DONT ap == no_action */
            continue;

        /* dest_apicid is same as /proc/irq/66/effective_affinity which is a 
         * subset of smp_affinity. Where hdw allows, both are same */
        kdbxp("%3d [%3d] 0x%08x %p %s(%s)\n", irq, cfg->vector,cfg->dest_apicid,
              desc, kdbx_hostsym(ap->handler), ap->name);

        if (ap->thread_fn) {
            kdbxp("  thread_fn: %s ts:%p\n", kdbx_hostsym(ap->thread_fn),
                  ap->thread);
        }
    }
#ifdef CONFIG_KDBX_FOR_XEN_DOM0
    kdbx_dump_guest_evtchn();
#endif
}

/* Dump irq desc table */
static kdbx_cpu_cmd_t kdb_usgf_dirq(void)
{
    kdbxp("dirq [cpu|all] : dump vector to irq bindings in this cpu IDT\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_dirq(int argc, const char **argv, struct pt_regs *regs)
{
    int cpu, ccpu = smp_processor_id();

    if (argc > 1) {
        if (!strcmp(argv[1], "all")) 
            cpu = -1;
        else if (!kdb_str2deci(argv[1], &cpu)) {
            kdbxp("Invalid cpu:%s\n", argv[1]);
            return kdb_usgf_dirq();
        }
    } else
        cpu = ccpu;

    if (cpu != -1) 
        kdbx_disp_irqs(cpu);
    else
        for_each_online_cpu(cpu) 
            kdbx_disp_irqs(cpu);

    return KDB_CPU_MAIN_KDB;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,35)
static void kdb_prnt_vec_irq_table(int cpu)
{
    int i, j; 

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    #define VECTOR_UNUSED VECTOR_UNDEFINED
#endif
    kdbxp("CPU %d : ", cpu);
    for (i=0, j=0; i < NR_VECTORS; i++) {
        if ( per_cpu(vector_irq, cpu)[i] == VECTOR_UNUSED )
            continue;

        kdbxp("(%3d:%3d) ", i, per_cpu(vector_irq, cpu)[i]);
        if (!(++j % 4))
            kdbxp("\n        ");
    }
    kdbxp("\n");
}

static kdbx_cpu_cmd_t kdb_usgf_dvit(void)
{
    kdbxp("dvit [cpu|all]: dump (per cpu)vector irq table\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_dvit(int argc, const char **argv, struct pt_regs *regs)
{
    int cpu, ccpu = smp_processor_id();

    if (argc > 1) {
        if (!strcmp(argv[1], "all")) 
            cpu = -1;
        else if (!kdb_str2deci(argv[1], &cpu)) {
            kdbxp("Invalid cpu:%s\n", argv[1]);
            return kdb_usgf_dvit();
        }
    } else
        cpu = ccpu;

    kdbxp("Per CPU vector irq table pairs (vector:irq) (all decimals):\n");
    if (cpu != -1) 
        kdb_prnt_vec_irq_table(cpu);
    else
        for_each_online_cpu(cpu) 
            kdb_prnt_vec_irq_table(cpu);

    return KDB_CPU_MAIN_KDB;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,14,35) */


struct idte {
    uint16_t offs0_15;
    uint16_t selector;
    uint16_t meta;
    uint16_t offs16_31;
    uint32_t offs32_63;
    uint32_t resvd;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#define gate_struct64 gate_struct
#endif

static void kdb_print_idte(int num, struct gate_struct64 *gsp) 
{
    struct irqaction *action; 
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    uint irq = __this_cpu_read(vector_irq[num]);
    struct irq_desc *desc = irq_to_desc(irq);
#else
    struct irq_desc *desc = __this_cpu_read(vector_irq[num]);
#endif
    struct idte *idtp = (struct idte *)gsp;
    uint16_t mta = idtp->meta;
    char dpl = ((mta & 0x6000) >> 13);
    char present = ((mta & 0x8000) >> 15);
    // int tval = ((mta & 0x300) >> 8);
    // char *type = (tval == 1) ? "Task" : ((tval== 2) ? "Intr" : "Trap");
    uint64_t addr = idtp->offs0_15 | ((uint64_t)idtp->offs16_31 << 16) | 
                    ((uint64_t)idtp->offs32_63 << 32);

    /* type is always "intr" */
    kdbxp("[%03d]: %04x %x %x %04x:%016lx ", num, mta, dpl, present,
          idtp->selector, addr); 
    kdbx_prnt_addr2sym(0, addr, "\n");

    /* each idte has fp, but not all of them are wired. they all go to 
     * common_interrupt and then do_IRQ */
    if ( IS_ERR_OR_NULL(desc) ) 
        return;      /* there is no device handler for this int */

    /* desc->handle_irq is handle_edge_irq etc that calls do_IRQ that calls 
     * device handlers below */
    // kdbxp("  irq_desc:%p handler:%p:", desc->handle_irq);
    // kdbx_prnt_addr2sym(0, (ulong)desc->handle_irq, "\n");

    if (desc->action == NULL)
        return;

    /* print device handlers that do_IRQ will call */
    kdbxp("    device handlers: ");
    for (action = desc->action; action; action = action->next) {
        kdbxp("\t%p:", action->handler);
        kdbx_prnt_addr2sym(0, (ulong)action->handler, "\n");
    }
}

/* Dump 64bit idt table currently on this cpu. Intel Vol 3 section 5.14.1 */
static kdbx_cpu_cmd_t kdb_usgf_didt(void)
{
    kdbxp("didt : dump IDT table on the current cpu\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_didt(int argc, const char **argv, struct pt_regs *regs)
{
    int i;
    struct gate_struct64 *idtp = idt_table;

    kdbxp("IDT at:%p (all hex except idt#)\n", idtp);
    kdbxp("idt#  meta DPL P addr   this_cpu(handler) if exists\n");

    for (i=0; i < 256; i++, idtp++) 
        kdb_print_idte(i, idtp);

    return KDB_CPU_MAIN_KDB;
}

struct gdte {             /* same for TSS and LDT */
    ulong limit0:16;
    ulong base0:24;       /* linear address base, not pa */
    ulong acctype:4;      /* Type: access rights */
    ulong S:1;            /* S: 0 = system, 1 = code/data */
    ulong DPL:2;          /* DPL */
    ulong P:1;            /* P: Segment Present */
    ulong limit1:4;
    ulong AVL:1;          /* AVL: avail for use by system software */
    ulong L:1;            /* L: 64bit code segment */
    ulong DB:1;           /* D/B */
    ulong G:1;            /* G: granularity */
    ulong base1:8;        /* linear address base, not pa */
};

union gdte_u {
    struct gdte gdte;
    u64 gval;
};

struct call_gdte {
    unsigned short offs0:16;
    unsigned short sel:16;
    unsigned short misc0:16;
    unsigned short offs1:16;
};

struct idt_gdte {
    unsigned long offs0:16;
    unsigned long sel:16;
    unsigned long ist:3;
    unsigned long unused0:13;
    unsigned long offs1:16;
};
union sgdte_u {
    struct call_gdte cgdte;
    struct idt_gdte igdte;
    u64 sgval;
};

#if 0
/* return binary form of a hex in string : max 4 chars 0000 to 1111 */
static char *kdb_ret_acctype(uint acctype)
{
    static char buf[16];
    char *p = buf;
    int i;

    if (acctype > 0xf) {
        buf[0] = buf[1] = buf[2] = buf[3] = '?';
        buf[5] = '\n';
        return buf;
    }
    for (i=0; i < 4; i++, p++, acctype=acctype>>1)
        *p = (acctype & 0x1) ? '1' : '0';

    return buf;
}
#endif

/* Display GDT table. IA-32e mode is assumed. */
/* first display non system descriptors then display system descriptors */
static kdbx_cpu_cmd_t kdb_usgf_dgdt(void)
{
    kdbxp("dgdt [gdt-ptr decimal-byte-size] dump GDT table on current "
         "cpu or for given vcpu\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_dgdt(int argc, const char **argv, struct pt_regs *regs)
{
    kdbxp("MUKESH: FIXME %s\n", __func__);
#if 0
    struct struct desc_ptr desc;
    union gdte_u u1;
    ulong start_addr, end_addr, taddr=0;
    int idx;

    if (argc > 1) {
        if (argc != 3)
            return kdb_usgf_dgdt();

        if (kdb_str2ulong(argv[1], (ulong *)&start_addr) && 
            kdb_str2deci(argv[2], (int *)&taddr)) {
            end_addr = start_addr + taddr;
        } else {
            kdbxp("dgdt: Bad arg:%s or %s\n", argv[1], argv[2]);
            return kdb_usgf_dgdt();
        }
    } else {
        __asm__ __volatile__ ("sgdt  (%0) \n" :: "a"(&desc) : "memory");
        start_addr = (ulong)desc.address; 
        end_addr = (ulong)desc.address + desc.size;
    }
    kdbxp("GDT: Will skip null desc at 0, start:%lx end:%lx\n", start_addr, 
         end_addr);
    kdbxp("[idx]   sel --- val --------  Accs DPL P AVL L DB G "
         "--Base Addr ----  Limit\n");
    kdbxp("                              Type\n");

    /* skip first 8 null bytes */
    /* the cpu multiplies the index by 8 and adds to GDT.base */
    for (taddr = start_addr+8; taddr < end_addr;  taddr += sizeof(ulong)) {

        /* not all entries are mapped. do this to avoid GP even if hyp */
        if (!kdbx_read_mem(taddr, (kdbbyt_t *)&u1, sizeof(u1), 0) || !u1.gval)
            continue;

        if (u1.gval == 0xffffffffffffffff || u1.gval == 0x5555555555555555)
            continue;               /* what an effin x86 mess */

        idx = (taddr - start_addr) / 8;
        if (u1.gdte.S == 0) {       /* System Desc are 16 bytes in 64bit mode */
            taddr += sizeof(ulong);
            continue;
        }
        kdbxp("[%04x] %04x %016lx  %4s  %x  %d  %d  %d  %d %d %016lx  %05x\n",
             idx, (idx<<3), u1.gval, kdb_ret_acctype(u1.gdte.acctype), 
             u1.gdte.DPL, 
             u1.gdte.P, u1.gdte.AVL, u1.gdte.L, u1.gdte.DB, u1.gdte.G,  
             (u64)((u64)u1.gdte.base0 | (u64)((u64)u1.gdte.base1<<24)), 
             u1.gdte.limit0 | (u1.gdte.limit1<<16));
    }

    kdbxp("\nSystem descriptors (S=0) : (skipping 0th entry)\n");
    for (taddr=start_addr+8;  taddr < end_addr;  taddr += sizeof(ulong)) {
        uint acctype;
        u64 upper, addr64=0;

        /* not all entries are mapped. do this to avoid GP even if hyp */
        if (kdbx_read_mem(taddr, (kdbbyt_t *)&u1, sizeof(u1), 0)==0 || 
            u1.gval == 0 || u1.gdte.S == 1) {
            continue;
        }
        idx = (taddr - start_addr) / 8;
        taddr += sizeof(ulong);
        if (kdbx_read_mem(taddr, (kdbbyt_t *)&upper, 8, 0) == 0) {
            kdbxp("Could not read upper 8 bytes of system desc\n");
            upper = 0;
        }
        acctype = u1.gdte.acctype;
        if (acctype != 2 && acctype != 9 && acctype != 11 && acctype !=12 &&
            acctype != 14 && acctype != 15)
            continue;

        kdbxp("[%04x] %04x val:%016lx DPL:%x P:%d type:%x ",
             idx, (idx<<3), u1.gval, u1.gdte.DPL, u1.gdte.P, acctype); 

        upper = (u64)((u64)(upper & 0xFFFFFFFF) << 32);

        /* Vol 3A: table: 3-2  page: 3-19 */
        if (acctype == 2) {
            kdbxp("LDT gate (0010)\n");
        }
        else if (acctype == 9) {
            kdbxp("TSS avail gate(1001)\n");
        }
        else if (acctype == 11) {
            kdbxp("TSS busy gate(1011)\n");
        }
        else if (acctype == 12) {
            kdbxp("CALL gate (1100)\n");
        }
        else if (acctype == 14) {
            kdbxp("IDT gate (1110)\n");
        }
        else if (acctype == 15) {
            kdbxp("Trap gate (1111)\n"); 
        }

        if (acctype == 2 || acctype == 9 || acctype == 11) {
            kdbxp("        AVL:%d G:%d Base Addr:%016lx Limit:%x\n",
                 u1.gdte.AVL, u1.gdte.G,  
                 (u64)((u64)u1.gdte.base0 | ((u64)u1.gdte.base1<<24)| upper),
                 (u32)u1.gdte.limit0 | (u32)((u32)u1.gdte.limit1<<16));

        } else if (acctype == 12) {
            union sgdte_u u2;
            u2.sgval = u1.gval;

            addr64 = (u64)((u64)u2.cgdte.offs0 | 
                           (u64)((u64)u2.cgdte.offs1<<16) | upper);
            kdbxp("        Entry: %04x:%016lx\n", u2.cgdte.sel, addr64);
        } else if (acctype == 14 || acctype == 15) {
            union sgdte_u u2;
            u2.sgval = u1.gval;

            addr64 = (u64)((u64)u2.igdte.offs0 | 
                           (u64)((u64)u2.igdte.offs1<<16) | upper);
            kdbxp("        Entry: %04x:%016lx ist:%03x\n", u2.igdte.sel, addr64,
                 u2.igdte.ist);
        } else 
            kdbxp(" Error: Unrecongized type:%lx\n", acctype);
    }
#endif
    return KDB_CPU_MAIN_KDB;
}

/* struct task_struct include/linux/sched.h */
static void kdb_display_task_struct(struct task_struct *tp)
{
    struct mm_struct *mm = tp ? tp->mm : NULL;
    struct thread_struct *ths = &tp->thread;

    if ( tp == NULL )
        return;

    kdbxp("task_struct: %p  pid:%d  tgid:%d  comm:%s\n", tp, tp->pid, tp->tgid,
          tp->comm);
    kdbxp("  state:%d (-1 unrunnable,  0 runnable,  >0 stopped)\n", tp->state);
    kdbxp("  stack(bottom): %p (top: %p)  flags: %x\n", tp->stack, 
          (char *)tp->stack+THREAD_SIZE, tp->flags);
    kdbxp("  on_cpu:%d  on_rq:%d  blocked:%d  blk_plug:%p  policy:%x \n",
          tp->on_cpu, tp->on_rq, tp->blocked, tp->plug, tp->policy);

    kdbx_print_regs(task_pt_regs(tp));

    kdbxp("  struct mm: %p\n", tp->mm);
    if ( mm ) {
        kdbxp("      pgd: %p nr_ptes: $%d task_size: %lx\n",
              mm->pgd, mm->nr_ptes, mm->task_size);
        kdbxp("      mmap_base: %lx highest_vm_end: %lx\n",
              mm->mmap_base, mm->highest_vm_end);
        kdbxp("      mm_users: $%d mm_count: $%d map_count: $%d\n", 
              mm->mm_users, mm->mm_count, mm->map_count);
        kdbxp("      tot-mapped-pgs: %x($%d)\n", mm->total_vm, mm->total_vm);
        kdbxp("\n");
    }
    kdbxp("  thread_struct: %p sp: %016lx  cr2: %016lx\n", ths, 
          ths->sp, ths->cr2);
    kdbxp("    io_bitmap_ptr: %p iopl: %x max: $%d\n", ths->io_bitmap_ptr,
          ths->iopl, ths->io_bitmap_max);
}

static kdbx_cpu_cmd_t kdb_usgf_ts(void)
{
    kdbxp("ts [pid|tp]: task struct for given pid or task_struct ptr\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_ts(int argc, const char **argv, struct pt_regs *regs)
{
    pid_t pid;
    struct task_struct *tp;

    if (argc > 1) {
        if (kdb_str2pid(argv[1], &pid, 0))
            tp = kdb_pid2tp(pid, 1);
        else if ( (tp = kdb_str2tp(argv[1], 0)) == NULL )
            return kdb_usgf_ts();
    } else
        tp = current;

    kdb_display_task_struct(tp);

    return KDB_CPU_MAIN_KDB;
}

static void kdb_show_threads(int show_ker, int show_usr)
{
    struct task_struct *p, *t;

    kdbxp("[UK]tsp        pid   tgid  nr_threads  state  comm\n");
    kdbxp("    (state:  -1 unrunnable,  0 runnable,  >0 stopped)\n");

    for_each_process(p) {
        int kth = p->flags & PF_KTHREAD;

        if ( (show_ker && kth) || (show_usr && !kth) ) {

            for_each_thread(p, t) {       /* includes parent process/thread */
                kdbxp("[%c]%p %5d %5d %4d %d %s\n", kth ? 'K' : 'U', t,
                      t->pid, t->tgid, get_nr_threads(t), t->state, t->comm);
            }
        }
    }
}

/* Display scheduler basic and extended info */
static kdbx_cpu_cmd_t kdb_usgf_tl(void)
{
    kdbxp("tl [k|u]: list of tasks. k=kernel only, u=user, def show both\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_tl(int argc, const char **argv, struct pt_regs *regs)
{
    int kernel = 0, user = 0;

    if (argc > 1) {
        if ( argv[1][0] == 'k' )
            kernel = 1;
        else if ( argv[1][0] == 'u' )
            user = 1;
        else
            return kdb_usgf_tl();
    } else
        kernel = user = 1;

    kdb_show_threads(kernel, user);
    return KDB_CPU_MAIN_KDB;
}

static char *kdb_print_sched_class(const struct sched_class *sp)
{
    if ( sp == &stop_sched_class )
        return "stop_sched_class";
    else if ( sp == &dl_sched_class )
        return "dl_sched (deadline sched)";
    else if ( sp == &rt_sched_class )
        return "rt_sched (realtime sched)";
    else if ( sp == &fair_sched_class )
        return "fair_sched_class";
    else if ( sp == &idle_sched_class )
        return "idle_sched_class";
    else 
        return "unknown sched class";
}

static noinline void kdb_display_runq(int cpu)
{
    struct task_struct *g, *p;
    struct rq *rq = cpu_rq(cpu);     /* kernel/sched/sched.h: nr_running */

    kdbxp("runq for cpu:%d nr_running:$%d nr_switches:$%d\n",
          cpu, rq->nr_running, rq->nr_switches);
    kdbxp("    current:%p [%s]  idle:%p [%s] stop:%p [%s]\n", 
          rq->curr, rq->curr->comm, rq->idle, rq->idle->comm,
          rq->stop, rq->stop->comm);

    kdbxp("    runq (next task could be any depending on policy): \n");

    for_each_process_thread(g, p) {  /* see print_rq() in kernel/sched/debug.c*/
        /* state: -1 unrunnable, 0 runnable, >0 stopped: */
        if (task_cpu(p) != cpu || p->state != TASK_RUNNING)
            continue;
        
        kdbxp("        pid: %d (%s) sched_class: %s\n",
              task_pid_nr(p), p->comm, kdb_print_sched_class(p->sched_class));
    }
    kdbxp("\n");
    return;

#if 0
task_state_to_char(p)
    list_for_each(lp, &vm_list) {
for_each_rt_rq
print_dl_rq
print_rt_rq
print_cfs_rq
#endif
}

static kdbx_cpu_cmd_t kdb_usgf_runq(void)
{
    kdbxp("runq [cpu]: show cpu runq\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_runq(int argc, const char **argv, struct pt_regs *regs)
{
    int tmpcpu, cpu = -1;

    if (argc > 1 ) {
        cpu = (int)simple_strtoul(argv[1], NULL, 0);     /* handles 0x */
        if ( ! kdb_cpu_valid(cpu) ) {
            kdbxp("Invalid cpu: %s\n", argv[1]);
            return kdb_usgf_runq();
        }
    }
    for_each_online_cpu(tmpcpu) {
        if (cpu == -1 || cpu == tmpcpu)
            kdb_display_runq(tmpcpu);
    }
    return KDB_CPU_MAIN_KDB;
}

/* Display scheduler basic and extended info */
static kdbx_cpu_cmd_t kdb_usgf_sched(void)
{
    kdbxp("sched: show schedular info\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_sched(int argc, const char **argv, struct pt_regs *regs)
{
    kdbxp("MUKESH: FIXME %s\n", __func__);
    return KDB_CPU_MAIN_KDB;
}

/* Display MMU basic and extended info */
static kdbx_cpu_cmd_t kdb_usgf_mmu(void)
{
    kdbxp("mmu: print basic MMU info\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_mmu(int argc, const char **argv, struct pt_regs *regs)
{
    /* si_meminfo() */
    kdbxp("total ram  : %lx pages\n", totalram_pages);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    kdbxp("free ram   : %lx pages\n", global_zone_page_state(NR_FREE_PAGES));
#else
    kdbxp("free ram   : %lx pages\n", global_page_state(NR_FREE_PAGES));
#endif
    kdbxp("max_pfn    : %lx\n", max_pfn);
    kdbxp("init_mm.pgd: %p\n", init_mm.pgd);
    kdbxp("PAGE_SIZE  : %x($%d)\n", PAGE_SIZE, PAGE_SIZE);
    kdbxp("PAGE_SHIFT : $%d\n", PAGE_SHIFT);
    kdbxp("PAGE_OFFSET: %016lx\n", PAGE_OFFSET);
    kdbxp("PAGE_MASK  : %016lx\n", PAGE_MASK);
    kdbxp("PTE_PFN_MASK      : %016lx\n", PTE_PFN_MASK);
    kdbxp("PTE_FLAGS_MASK    : %016lx\n", PTE_FLAGS_MASK);
    kdbxp("PHYSICAL_PAGE_MASK: %016lx\n", PHYSICAL_PAGE_MASK);
    kdbxp("PMD_SHIFT     : $%d\n", PMD_SHIFT);
    kdbxp("PMD_PAGE_SIZE     : %016lx\n", PMD_PAGE_SIZE);
    kdbxp("PMD_PAGE_MASK     : %016lx\n", PMD_PAGE_MASK);
    kdbxp("PUD_SHIFT    : $%d\n", PUD_SHIFT);
    kdbxp("PGDIR_SHIFT  : $%d\n", PGDIR_SHIFT);
    kdbxp("PHYSICAL_PUD_PAGE_MASK: %016lx\n", PHYSICAL_PUD_PAGE_MASK);
    kdbxp("PUD_MASK     : %016lx\n", PUD_MASK);
    kdbxp("HPAGE_SHIFT       : %016lx\n", HPAGE_SHIFT);
    kdbxp("HPAGE_SIZE        : %016lx\n", HPAGE_SIZE);
    kdbxp("HPAGE_MASK        : %016lx\n", HPAGE_MASK);
    kdbxp("HUGETLB_PAGE_ORDER: %016lx\n", HUGETLB_PAGE_ORDER);
    kdbxp("KVM_PFN_ERR_FAULT : %016lx\n", KVM_PFN_ERR_FAULT);
    kdbxp("\n");
    kdbxp("__KERNEL_CS    : %x\n", __KERNEL_CS);
    kdbxp("__KERNEL_DS/SS : %x\n", __KERNEL_DS);
    kdbxp("__USER_CS : %x\n", __USER_CS);
    kdbxp("__USER_DS : %x\n", __USER_DS);
    kdbxp("\n");
    kdbxp("IRQ_STACK_SIZE: %d 0x%lx\n", IRQ_STACK_SIZE, IRQ_STACK_SIZE);
    kdbxp("EXCEPTION_STKSZ: %d 0x%lx\n", EXCEPTION_STKSZ, EXCEPTION_STKSZ);
    kdbxp("DEBUG_STKSZ: %d 0x%lx\n", DEBUG_STKSZ, DEBUG_STKSZ);
    kdbxp("THREAD_SIZE(stack size): %d 0x%lx\n", THREAD_SIZE, THREAD_SIZE);
    kdbxp("\n");

    kdbxp("kvm_largepages_enabled (EPT): %c\n", 
          kvm_largepages_enabled() ? 'Y' : 'N');
    kdbxp("\n");

    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_iommu(void)
{
    kdbxp("dump iommu p2m table for all domains\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_iommu(int argc, const char **argv, struct pt_regs *regs)
{
    kdbxp("FIXME\n");
    return KDB_CPU_MAIN_KDB;
}

#if 0
static void 
kdb_pr_pg_pgt_flds(unsigned long type_info)
{
    switch (type_info & PGT_type_mask) {
        case (PGT_l1_page_table):
            kdbxp("    page is PGT_l1_page_table\n");
            break;
        case PGT_l2_page_table:
            kdbxp("    page is PGT_l2_page_table\n");
            break;
        case PGT_l3_page_table:
            kdbxp("    page is PGT_l3_page_table\n");
            break;
        case PGT_l4_page_table:
            kdbxp("    page is PGT_l4_page_table\n");
            break;
        case PGT_seg_desc_page:
            kdbxp("    page is seg desc page\n");
            break;
        case PGT_writable_page:
            kdbxp("    page is writable page\n");
            break;
        case PGT_shared_page:
            kdbxp("    page is shared page\n");
            break;
    }
    if (type_info & PGT_pinned)
        kdbxp("    page is pinned\n");
    if (type_info & PGT_validated)
        kdbxp("    page is validated\n");
    if (type_info & PGT_pae_xen_l2)
        kdbxp("    page is PGT_pae_xen_l2\n");
    if (type_info & PGT_partial)
        kdbxp("    page is PGT_partial\n");
    if (type_info & PGT_locked)
        kdbxp("    page is PGT_locked\n");
}

static void kdb_pr_pg_pgc_flds(unsigned long count_info)
{
    if (count_info & PGC_allocated)
        kdbxp("  PGC_allocated");
    if (count_info & PGC_xen_heap)
        kdbxp("  PGC_xen_heap");
    if (count_info & PGC_page_table)
        kdbxp("  PGC_page_table");
    if (count_info & PGC_broken)
        kdbxp("  PGC_broken");
#if XEN_VERSION < 4                                 /* xen 3.x.x */
    if (count_info & PGC_offlining)
        kdbxp("  PGC_offlining");
    if (count_info & PGC_offlined)
        kdbxp("  PGC_offlined");
#else
    if (count_info & PGC_state_inuse)
        kdbxp("  PGC_inuse");
    if (count_info & PGC_state_offlining)
        kdbxp("  PGC_state_offlining");
    if (count_info & PGC_state_offlined)
        kdbxp("  PGC_state_offlined");
    if (count_info & PGC_state_free)
        kdbxp("  PGC_state_free");
#endif
    kdbxp("\n");
}
#endif

static void kdb_display_page_flags(ulong flags)
{
    kdbxp("  flags: %016lx :  ", flags); 
    if (test_bit(PG_locked, &flags))
        kdbxp("  PG_locked");
    if (test_bit(PG_error, &flags))
        kdbxp("  PG_error");
    if (test_bit(PG_referenced, &flags))
        kdbxp("  PG_referenced");
    if (test_bit(PG_uptodate, &flags))
        kdbxp("  PG_uptodate");
    if (test_bit(PG_dirty, &flags))
        kdbxp("  PG_dirty");
    if (test_bit(PG_lru, &flags))
        kdbxp("  PG_lru");
    if (test_bit(PG_active, &flags))
        kdbxp("  PG_active");
    if (test_bit(PG_slab, &flags))
        kdbxp("  PG_slab");
    if (test_bit(PG_owner_priv_1, &flags))
        kdbxp("  PG_owner_priv_1");
    if (test_bit(PG_arch_1, &flags))
        kdbxp("  PG_arch_1");
    if (test_bit(PG_reserved, &flags))
        kdbxp("  PG_reserved");
    if (test_bit(PG_private, &flags))
        kdbxp("  PG_private");
    if (test_bit(PG_private_2, &flags))
        kdbxp("  PG_private_2");
    if (test_bit(PG_writeback, &flags))
        kdbxp("  PG_writeback");
    if (test_bit(PG_head, &flags))
        kdbxp("  PG_head");
    if (test_bit(PG_swapcache, &flags))
        kdbxp("  PG_swapcache");
    if (test_bit(PG_mappedtodisk, &flags))
        kdbxp("  PG_mappedtodisk");
    if (test_bit(PG_reclaim, &flags))
        kdbxp("  PG_reclaim");
    if (test_bit(PG_swapbacked, &flags))
        kdbxp("  PG_swapbacked");
    if (test_bit(PG_unevictable, &flags))
        kdbxp("  PG_unevictable");
#ifdef CONFIG_MMU
    if (test_bit(PG_mlocked, &flags))
        kdbxp("  PG_mlocked");
#endif
#ifdef CONFIG_ARCH_USES_PG_UNCACHED
    if (test_bit(PG_uncached, &flags))
        kdbxp("  PG_uncached");
#endif
#ifdef CONFIG_MEMORY_FAILURE
    if (test_bit(PG_hwpoison, &flags))
        kdbxp("  PG_hwpoison");
#endif
    kdbxp("\n");
}

/* print struct page_info{} given ptr to it or an mfn */
static kdbx_cpu_cmd_t kdb_usgf_dpage(void)
{
    kdbxp("dpage pfn|page-ptr : Display struct page\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_dpage(int argc, const char **argv, struct pt_regs *regs)
{
    unsigned long val;
    struct page *pgp;  /* include/linux/mm_types.h */

    if (argc < 2) 
        return kdb_usgf_dpage();

    if (kdb_str2ulong(argv[1], &val) == 0) {
        kdbxp("Invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    if ( page_is_ram(val) )     /* val is pfn? */
        pgp = pfn_to_page(val);
    else
        pgp = (struct page *)val;
    
    if (pgp < vmemmap || pgp >= vmemmap + max_pfn) {
        kdbxp("Invalid page ptr:%p\n", pgp);
        return KDB_CPU_MAIN_KDB;
    }

    kdbxp("Page Info: %p   (include/linux/mm_types.h)\n", pgp);
    kdb_display_page_flags(pgp->flags);
    kdbxp("  mapping: %p\n", pgp->mapping);
    kdbxp("  next word: %p", pgp->freelist);
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && USE_SPLIT_PMD_PTLOCKS
    kdbxp("  (pmd_huge_pte is defined)\n");
#else
    kdbxp("  (pmd_huge_pte is NOT defined)\n");
#endif
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
        defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
    kdbxp("  next word:%016lx\n", pgp->counters);
#else
    kdbxp("  next word:%08lx\n", pgp->counters);
#endif

    kdbxp("  _mapcount/units: %x inuse/obj/fr: %x/%x/%x\n", pgp->units,
          pgp->inuse, pgp->objects, pgp->frozen);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
    kdbxp("  _count: %x\n", pgp->_count.counter);
#else
    kdbxp("  _count: %x\n", pgp->_refcount.counter);
#endif
    kdbxp("  private: %016lx\n", pgp->private);

#if defined(WANT_PAGE_VIRTUAL)
    kdbxp("  virtual: %p\n", pgp->virtual);
#endif /* WANT_PAGE_VIRTUAL */  
#ifdef CONFIG_WANT_PAGE_DEBUG_FLAGS
    kdbxp("  debug_flags: %016lx\n", pgp->debug_flags);
#endif /* WANT_PAGE_VIRTUAL */  

    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_wpt(void)
{
    kdbxp("wpt addr [pid]: walk kernel page table\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_wpt(int argc, const char **argv, struct pt_regs *regs)
{
    unsigned long addr;
    pid_t gpid = 0;
    struct kvm_vcpu *vp = NULL;

    if (argc <= 1) 
        return kdb_usgf_wpt();

    if ((kdb_str2ulong(argv[1], &addr) == 0)) {
        kdbxp("Invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    if (argc >= 3 ) {
        if ( kdb_str2pid(argv[2], &gpid, 1)==0 || 
             (vp = kdbx_pid_to_vcpu(gpid, 1))==0 )
            return KDB_CPU_MAIN_KDB;
    }

    kdbx_walk_pt(addr, vp);  /* kdbx_mem_rw.c */
    return KDB_CPU_MAIN_KDB;
}

/* display asked msr value */
static kdbx_cpu_cmd_t kdb_usgf_dmsr(void)
{
    kdbxp("dmsr address : Display msr value\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_dmsr(int argc, const char **argv, struct pt_regs *regs)
{
    unsigned long addr, val;

    if (argc <= 1) 
        return kdb_usgf_dmsr();

    if ((kdb_str2ulong(argv[1], &addr) == 0)) {
        kdbxp("Invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    rdmsrl(addr, val);
    kdbxp("msr: %lx  val:%lx\n", addr, val);

    return KDB_CPU_MAIN_KDB;
}

/* execute cpuid for given value */
static kdbx_cpu_cmd_t kdb_usgf_cpuid(void)
{
    kdbxp("cpuid eax : Display cpuid value returned in rax\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_cpuid(int argc, const char **argv, struct pt_regs *regs)
{
    unsigned int ax=0, bx=0, cx=0, dx=0;

    if (argc <= 1) 
        return kdb_usgf_cpuid();

    if ((kdb_str2ulong(argv[1], (ulong *)&ax) == 0)) {
        kdbxp("Invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
#if 0
    __asm__ __volatile__ (
            /* "pushl %%rax  \n" */

            "movl %0, %%rax  \n"
            "cpuid           \n" 
            : "=&a" (rax), "=b" (rbx), "=c" (rcx), "=d" (rdx)
            : "0" (rax)
            : "rax", "rbx", "rcx", "rdx", "memory");
#endif
    cpuid(ax, &ax, &bx, &cx, &dx);
    kdbxp("ax: %08lx  bx:%08lx cx:%08lx dx:%08lx\n", ax, bx, cx, dx);
    return KDB_CPU_MAIN_KDB;
}

static void kdbx_walk_wq(struct wait_queue_head *wqh)
{
    struct wait_queue_entry *wqe;

    if (wqh == NULL || list_empty(&wqh->head) ) {
        kdbxp("q: %wqh is empty/null\n");
        return;
    }
    kdbxp("wq head: %p  flags(1==WQ_FLAG_EXCLUSIVE)\n", wqh->head);
    list_for_each_entry(wqe, &wqh->head, entry) {
        struct task_struct *ts = wqe->private;
        wait_queue_func_t fp = wqe->func;

        kdbxp("ts:%p(%s) f:%p(%s) flags:%x\n", ts, ts->comm, fp,
              kdbx_hostsym(fp), wqe->flags);
    }
}

static kdbx_cpu_cmd_t kdb_usgf_wq(void)
{
    kdbxp("wq wait_queue_head (not wqh->head): walk wait queue\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_wq(int argc, const char **argv, struct pt_regs *regs)
{
    struct wait_queue_head *wqh;

    if (argc < 2) 
        return kdb_usgf_wq();

    if (kdb_str2ulong(argv[1], (ulong *)&wqh) == 0) {
        kdbxp("wqh: Invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    kdbx_walk_wq(wqh);
    return KDB_CPU_MAIN_KDB;
}


/* Save symbols info for a guest */
static kdbx_cpu_cmd_t kdb_usgf_sym(void)
{
   kdbxp(">>> MAKE sure guest is booted with nokaslr\n");
   kdbxp("sym gpid &kallsyms_names &kallsyms_num_syms &kallsyms_sizes\n");
   kdbxp("   &kallsyms_relative_base &kallsyms_offsets (ol7 default) OR\n");
   kdbxp("sym gpid &kallsyms_names &kallsyms_num_syms &kallsyms_addresses\n");
   kdbxp("\t[&kallsyms_token_table] [&kallsyms_token_index]\n");
   kdbxp("\ttoken _table and _index MUST be specified for el5 and above\n");
   kdbxp("\tgpid : any guest pid/lwp/tid. (not tgid)\n");

   return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_sym(int argc, const char **argv, struct pt_regs *regs)
{
    ulong namesp, nump, addrap, sizes, relbase, offsets, toktblp, tokidxp;
    pid_t gpid;

    namesp = nump = addrap = sizes = relbase = offsets = toktblp = tokidxp = 0;

    /* [el4 == 5]  [el5 and el6 == 7]  [el7 == 9] */  
    if (argc != 5 && argc != 7 && argc != 9) {
        return kdb_usgf_sym();
    }

    /* common args */
    if (kdb_str2pid(argv[1], &gpid, 1)    &&
        kdbx_pid_to_vcpu(gpid, 1)         &&
        kdb_str2ulong(argv[2], &namesp)   &&
        kdb_str2ulong(argv[3], &nump))
            ;
    else
        return kdb_usgf_sym();

    if (argc == 5 && kdb_str2ulong(argv[4], &addrap))
        ;   /* all good for el4 */
    else if (argc == 7 &&
        kdb_str2ulong(argv[4], &addrap)   &&
        kdb_str2ulong(argv[5], &toktblp)  && 
        kdb_str2ulong(argv[6], &tokidxp)) 
            ;   /* all good for el5 and el6 */
    else if (argc == 9 &&
        kdb_str2ulong(argv[4], &sizes)  &&
        kdb_str2ulong(argv[5], &relbase)  &&
        kdb_str2ulong(argv[6], &offsets)  &&
        kdb_str2ulong(argv[7], &toktblp)  && 
        kdb_str2ulong(argv[8], &tokidxp)) 
            ;   /* all good for el7 */
    else
        return kdb_usgf_sym();

    kdbxp("gpid:%d namesp:%lx nump:%lx addrs:%lx sizes:%lx relbase:%lx\n",
          gpid, namesp, nump, addrap, sizes, relbase);
    kdbxp("offsets:%lx toktblp:%lx tokidxp:%lx\n", offsets, toktblp, tokidxp);
         
    kdbxp(">>> MAKE sure guest is booted with nokaslr\n");
    kdbx_sav_guest_syminfo(gpid, namesp, nump, addrap, sizes, relbase, offsets, 
                           toktblp, tokidxp);
    return KDB_CPU_MAIN_KDB;
}

/* Display modules loaded in linux guest */
static kdbx_cpu_cmd_t kdb_usgf_mods(void)
{
   kdbxp("mods : display all loaded modules\n");
   return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_mods(int argc, const char **argv, struct pt_regs *regs)
{
    kdbxp("MUKESH: FIXME %s\n", __func__);
    return KDB_CPU_MAIN_KDB;
}

static ulong kdbx_ept_walk_table(struct kvm_vcpu *vp, ulong gfn, int pr_info)
{
    int i;
    struct page *pg;
    union kdbx_ept_entry *eptep = NULL, *eptpg;
    unsigned long mfn = 0, gfn_remainder = gfn;
    struct kvm_mmu *mm = &vp->arch.mmu;
    unsigned long eptmfn = mm->root_hpa >> PAGE_SHIFT;   /* ~ EPTPTR */

    KDBGP1("wept: vp:%p gfn:%lx pr:%d\n", vp, gfn, pr_info);

    if ( eptmfn == 0 || eptmfn > max_pfn) {
        kdbxp("EPT ptr mfn is invalid: %lx\n", eptmfn);
        return 0;
    }
    if ( !kdb_gfn_valid(vp, gfn, 1) ) {
        KDBGP("wept: gfn:%lx is invalid\n", gfn);
        return 0;
    }

    pg = pfn_to_page(eptmfn);
    eptpg = page_to_virt(pg); /* kmap() will call __schedule(), don't call it */
    if ( eptpg == NULL ) {
        kdbxp("Unable to map ept mfn:%lx pg:%p\n", eptmfn, pg);
        return 0;
    }

    for ( i = get_ept_level(vp) - 1; i >= 0; i-- )
    {
        u32 index;

        index = gfn_remainder >> (i * EPT_TABLE_ORDER);
        eptep = eptpg + index;

        if ( pr_info )
            kdbxp(" ptr: %p  entry: %016lx mfn:%lx\n", eptep, eptep->epte, 
                  eptep->mfn);

        if ( (i == 0) || !is_epte_present(eptep) )
            break;
        else if ( is_epte_superpage(eptep) ) {
            if ( i == 3 ) {
                kdbxp("superpage at level 3.. confused\n");
                kdbxp("  entry:%lx gfn:%lx vp:%p\n", eptep->epte, gfn, vp);
            } else if ( i == 2 )
                kdbxp("1G superpage. Use bits 0-29 of guest Phys Addr\n");
            else
                kdbxp("2M superpage. Use bits 0-20 of guest Phys Addr\n");

            break;

        } else {

            mfn = eptep->mfn;

            gfn_remainder &= (1UL << (i * EPT_TABLE_ORDER)) - 1;
            pg = pfn_to_page(mfn);
            eptpg = page_to_virt(pg);
            if ( eptpg == NULL ) {
                kdbxp("Unable to map mfn:%lx pg:%p\n", mfn, pg);
                break;
            }
        }
    }
    if ( i ) {
        kdbxp("FIXME: ept using large page. i:%d\n", i);
        return 0;
    }
    mfn = eptep ? eptep->mfn : 0;
    KDBGP1("wept: return mfn:%lx\n", mfn);

    return mfn;
}

static kdbx_cpu_cmd_t kdb_usgf_wept(void)
{
    kdbxp("wept pid/vcpu gfn: walk ept table for given pid and gfn\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_wept(int argc, const char **argv, struct pt_regs *regs)
{
    struct kvm_vcpu *v;
    ulong gfn;

    if (argc != 3)
        return kdb_usgf_wept();

    if ( (v=kdb_pidvcpustr2vcpu(argv[1], 0)) && kdb_str2ulong(argv[2], &gfn) )
        kdbx_ept_walk_table(v, gfn, 1);
    else
        kdb_usgf_wept();

    return KDB_CPU_MAIN_KDB;
}

ulong kdbx_p2m(struct kvm_vcpu *vp, ulong gfn)
{
    ulong mfn;

    KDBGP1("p2m: vp:%p gfn:%lx\n", vp, gfn);
    if ( vp ) {
        if ( (mfn=kdbx_ept_walk_table(vp, gfn, 0)) == 0 ) {
            /* bad things will happen if gfn is not valid */
            struct kvm *kp = vp->kvm;
            struct kvm_memslots *slots = kvm_memslots(kp);

            if ( search_memslots(slots, gfn) ) {
                struct task_struct *savcur = current;
                struct task_struct *tp = pid_task(vp->pid, PIDTYPE_PID);

                if (tp == NULL) {
                    kdbxp("p2m: invalid task struct:%p\n", tp);
                    return 0;
                }

                /* gfn_to_pfn_atomic will use current to walk the user hva
                 * memory lookups, so will panic if current is not VM pid */
                __this_cpu_write(current_task, tp);
                mfn = gfn_to_pfn_atomic(kp, gfn);
                __this_cpu_write(current_task, savcur);
                if ( mfn == KVM_PFN_ERR_FAULT ) {
                    kdbxp("gfn_to_pfn: ret KVM_PFN_ERR_FAULT:%lx gfn:%lx\n",
                          KVM_PFN_ERR_FAULT, gfn);
                    mfn = 0;
                }
            }
        }
        KDBGP1("p2m ret: for gfn:%lx mfn:%lx\n", gfn, mfn);
        return mfn;
    }
    return gfn;   /* host: gfn is pfn */
}
EXPORT_SYMBOL_GPL(kdbx_p2m);

static kdbx_cpu_cmd_t kdb_usgf_p2m(void)
{
    kdbxp("p2m pid/vcpu gfn: print pfn, ie, mfn for the gfn, ie, pfn\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_p2m(int argc, const char **argv, struct pt_regs *regs)
{
    struct kvm_vcpu *vp;
    ulong gfn, pfn;

    if (argc != 3)
        return kdb_usgf_p2m();

    if ( (vp=kdb_pidvcpustr2vcpu(argv[1], 0)) && kdb_str2ulong(argv[2], &gfn) ){
        pfn = kdbx_p2m(vp, gfn);
        kdbxp("gfn: %016lx  pfn:%016lx\n", gfn, pfn);
    } else
        kdb_usgf_p2m();

    return KDB_CPU_MAIN_KDB;
}

/* Display VMCS or VMCB */
static kdbx_cpu_cmd_t kdb_usgf_dvmc(void)
{
    kdbxp("dvmc [pid/vcpu]: Dump vmcs/vmcb\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_dvmc(int argc, const char **argv, struct pt_regs *regs)
{
    struct kvm_vcpu *vp = NULL;

    if ( argc > 1 && (vp = kdb_pidvcpustr2vcpu(argv[1], 1)) == NULL ) 
        return kdb_usgf_dvmc();

    if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
        // kdb_all_cpu_flush_vmcs();
        kdbx_dump_vmcs(vp);
    } else {
        kdbxp("Fixme on AMD\n");
    }
    return KDB_CPU_MAIN_KDB;
}


static void kdb_display_kvm_mmu(struct kvm_vcpu_arch *ap)
{
    unsigned long sz, offs;
    char buf[KSYM_NAME_LEN+1];
    struct kvm_mmu *mm = ap ? &ap->mmu : NULL;

    if ( mm == NULL )
        return;

    kdbxp("    kvm_mmu mmu:\n");

    kallsyms_lookup((ulong)mm->get_cr3, &sz, &offs, NULL, buf);
    kdbxp("      get_cr3:%s", buf);
    kallsyms_lookup((ulong)mm->translate_gpa, &sz, &offs, NULL, buf);
    kdbxp("      translate_gpa:%s\n", buf);

    kdbxp("      root_hpa:%016lx root_level:%x\n", mm->root_hpa,
          mm->root_level);
    kdbxp("      direct_map:%d nx:%d pae_root:%p lm_root:%p\n", mm->direct_map,
          mm->nx, mm->pae_root, mm->lm_root);
    kdbxp("      pdptrs[0]:%p  [1]:%p\n", mm->pdptrs[0], mm->pdptrs[1]); 
    kdbxp("            [2]:%p  [3]:%p\n", mm->pdptrs[2], mm->pdptrs[3]); 
}

static void kdb_display_varch(struct kvm_vcpu *vp)
{
    struct pt_regs regs;
    struct kvm_vcpu_arch *ap = vp ? &vp->arch : NULL;
    struct kvm_queued_exception *qe = ap ? &ap->exception : NULL;
    struct kvm_queued_interrupt *qi = ap ? &ap->interrupt : NULL;

    if (ap == NULL)
        return;
    
    kdbxp("kvm_vcpu_arch:%p regs_avail:%x regs_dirty:%x\n", ap, ap->regs_avail,
          ap->regs_dirty);
    kdbxp("  cr0:%016lx cr0-guest:%016lx\n", ap->cr0, ap->cr0_guest_owned_bits);
    kdbxp("  cr4:%016lx cr4-guest:%016lx\n", ap->cr4, ap->cr4_guest_owned_bits);
    kdbxp("  cr2:%016lx cr3:%016lx cr8::%016lx\n", ap->cr2, ap->cr3, ap->cr8);

    kdbx_vcpu_to_ptregs(vp, &regs);
    kdbx_print_regs(&regs);

    kdbxp("  hflags:%08x efer:%016lx mp_state:%08x apf.halted: %d\n",
          ap->hflags, ap->efer, ap->mp_state, ap->apf.halted);
    kdbxp("  apic_base:%016lx apic_att:%016lx apic:%p\n", ap->apic_base,
          ap->apic_attention, ap->apic);
    kdbxp("  mtrr_state:%p pat:%016lx tpr_acc:%d\n", &ap->mtrr_state, ap->pat,
          !!ap->tpr_access_reporting);
    kdbxp("  mmio_gva:%016lx access:%x gfn:%016lx\n", ap->mmio_gva,
          ap->access, ap->mmio_gfn);
    kdbxp("  queued exception: pend:%d injected:%d nr:%d err:%d errcode:%d\n", 
          qe->pending, qe->injected, qe->nr, qe->has_error_code, 
          qe->error_code);
    kdbxp("  queued interrupt: injected:%d soft:%d nr:%d\n", 
          qi->injected, qi->soft, qi->nr);
    kdbxp("  exit_qual:%016lx fault_shad:%d pv_unhalt:%d\n", 
          ap->exit_qualification, !!ap->write_fault_to_shadow_pgtable, 
          !!ap->pv.pv_unhalted);

    kdb_display_kvm_mmu(ap);
}

static kdbx_cpu_cmd_t kdb_usgf_varch(void)
{
    kdbxp("varch [*vcpu*-ptr] : display current/vcpu-ptr vcpu arch info\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t 
kdb_cmdf_varch(int argc, const char **argv, struct pt_regs *regs)
{
    struct kvm_vcpu *v = NULL;

    if (argc > 2)
        kdb_usgf_varch();
    else if (argc <= 1)
        kdb_display_varch(v);
    else if (kdb_str2ulong(argv[1], (ulong *)&v) && kdb_vcpu_valid(v))
        kdb_display_varch(v);
    else 
        kdbxp("Invalid usage/argument:%s v:%lx\n", argv[1], (long)v);

    return KDB_CPU_MAIN_KDB;
}

static void kdb_display_vcpu(struct kvm_vcpu *vp)
{
    struct task_struct *tp;

    if ( vp == NULL )
        return;

    tp = pid_task(vp->pid, PIDTYPE_PID);
    kdbxp("vcpu: %p  vcpu_id:%d kvm:%p pid:%d(?) lwp:%d\n", vp, vp->vcpu_id,
          vp->kvm, vp->preempted, tp ? tp->pid : -1, tp ? tp->tgid : -1);

    kdbxp("\tcpu:%d srcu_idx:%d mode:%d requests:%d", vp->cpu, vp->srcu_idx,
          vp->mode, vp->requests);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    kdbxp(" guest_debug:%d preempted:%d \n", vp->guest_debug, vp->preempted);
#else
    kdbxp(" fpu_active:%d preempted:%d \n", vp->fpu_active, vp->preempted);
#endif
#ifdef CONFIG_HAS_IOMEM
    kdbxp("\tmmio_needed:%d mmio_read_comp:%d mmio_is_write:%d\n",
          vp->mmio_needed, vp->mmio_read_completed, vp->mmio_is_write);
    kdbxp("\tcur_frag:%d nr_frag:%d mmio_frags:%p\n", vp->mmio_cur_fragment,
          vp->mmio_nr_fragments, vp->mmio_fragments);
#endif
#ifdef CONFIG_KVM_ASYNC_PF
    kdbxp("\tasync_pf:%p", &vp->async_pf);
#endif
#ifdef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
    kdbxp("\tspin_loop:%p\n", &vp->spin_loop);
#endif
    kdbxp("\n");
    kdb_display_varch(vp);
    kdbx_display_vvmx(vp);
}

static kdbx_cpu_cmd_t kdb_usgf_vcpu(void)
{
    kdbxp("vcpu [pid/vcpu-ptr] : display current/vcpu-ptr vcpu info\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t 
kdb_cmdf_vcpu(int argc, const char **argv, struct pt_regs *regs)
{
    struct kvm_vcpu *vp;

    if (argc > 2) {
        kdb_usgf_vcpu();

    } else if (argc <= 1) {
        kdbx_ret_curr_vcpu_info(&vp, NULL, NULL);
        kdb_display_vcpu(vp);

    } else if ( (vp = kdb_pidvcpustr2vcpu(argv[1], 0)) ) {
        kdb_display_vcpu(vp);

    } else 
        kdb_usgf_vcpu();

    return KDB_CPU_MAIN_KDB;
}

static void kdbx_disp_struct_device(struct device *dev, int prshort)
{
    kdbxp("  device: name:%s  device_type name:%s\n",
          dev_name(dev), dev->type ? dev->type->name : "\0"); 
    kdbxp("    bus_type:{nm:%s devnm:%s} dd:{%s mod:%s}\n",
          dev->bus ? dev->bus->name : "\0", 
          dev->bus ? dev->bus->dev_name : "\0",
          dev->driver ? dev->driver->name : "\0", 
          dev->driver ? dev->driver->mod_name : "\0");
    
    if (prshort)
        return;
    /* long info, dump more */
}

/* also called from virtio_scsi.c */
void kdbx_disp_virtio_device(struct virtio_device *vdevp, int prshort)
{
    struct device *dev=&vdevp->dev;      /* include/linux/device.h */

    kdbxp("  idx(on virt bus): %d  virtio_device_id:%d\n", vdevp->index,
          vdevp->id);
    if ( dev == NULL )
        return;

    kdbx_disp_struct_device(dev, 1);
}

static void kdbx_disp_scsi_host(struct Scsi_Host *sh)
{
    kdbxp("  Scsi_Host: %p\n", sh);
    kdbxp("    nr_hw_queues: %d  use_blk_mq:%d  active_mode:%d\n",
          sh->nr_hw_queues, sh->use_blk_mq, sh->active_mode);
    kdbxp("    work_q_name: %s  dma_dev:%p\n", sh->work_q_name, sh->dma_dev);
}

static kdbx_cpu_cmd_t kdb_usgf_virtscsi(void)
{
    kdbxp("virtscsi addr: dump virtio_scsi struct\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_virtscsi(int argc, const char **argv, struct pt_regs *regs)
{
    struct virtio_scsi *vs;

    if ( argc < 2)
        return kdb_usgf_virtscsi();

    if (!kdb_str2addr(argv[1], (kdbva_t *)&vs, 0)) {
        kdbxp("Invalid addr: %lx\n", vs);
        return KDB_CPU_MAIN_KDB;
    }
    kdbx_disp_virtio_scsi(vs);    /* drivers/scsi/virtio_scsi.c */
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_virtq(void)
{
    kdbxp("virtq addr: dump virtqueue struct\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_virtq(int argc, const char **argv, struct pt_regs *regs)
{
    struct virtqueue *vq;

    if ( argc < 2)
        return kdb_usgf_virtq();

    if (!kdb_str2addr(argv[1], (kdbva_t *)&vq, 0)) {
        kdbxp("Invalid addr: %lx\n", vq);
        return KDB_CPU_MAIN_KDB;
    }
    kdbx_disp_virtq(vq);        /* drivers/virtio/virtio_ring.c */

    return KDB_CPU_MAIN_KDB;
}

static int kdbx_virtqueues(struct virtio_device *vdev, int print)
{
    struct virtqueue *vq;
    int i = 0;

    virtio_device_for_each_vq(vdev, vq) {
        // kdbx_disp_virtq(vq);        /* drivers/virtio/virtio_ring.c */
        if ( print )
            kdbxp("[%d]:%p \n", i++, vq);
        i++;
        if ( print && i % 4 == 0 )
            kdbxp("\n");
    };
    return i;
}

static kdbx_cpu_cmd_t kdb_usgf_vdevvq(void)
{
    kdbxp("vdevvq virtio_device* : display vqs for this virtio device\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_vdevvq(int argc, const char **argv, struct pt_regs *regs)
{
    struct virtio_device *vdev;

    if ( argc < 2)
        return kdb_usgf_vdevvq();

    if (!kdb_str2addr(argv[1], (kdbva_t *)&vdev, 0)) {
        kdbxp("Invalid addr: %lx\n", vdev);
        return KDB_CPU_MAIN_KDB;
    }
    kdbxp("virtio_device: %p type: %d(%s)\n",
          vdev->id.device, kdbx_virtdev_to_str(vdev->id.device));
    kdbxp("  virtqueus:\n");
    kdbx_virtqueues(vdev, 1);

    return KDB_CPU_MAIN_KDB;
}

/* called for each device for the virtio driver on the virtio bus */
static int kdbx_display_virtio_device(struct virtio_device *vd)
{
    struct device *dev = &vd->dev;

    kdbxp("\n virtio_device: %p  index: $%d  priv: %p\n", vd, vd->index,
          vd->priv);
    kdbxp("   virt-device: %d(%s)  device.name: %s\n", vd->id.device,
          kdbx_virtdev_to_str(vd->id.device), dev_name(dev)); 
    kdbxp("   num of virtqueues: %d\n", kdbx_virtqueues(vd, 0));

    if ( vd->priv == NULL )
        return 0;

    if ( vd->id.device == VIRTIO_ID_BLOCK )
        kdbx_disp_virtio_blk(vd->priv);  /* drivers/block/virtio_blk.c */

    else if ( vd->id.device == VIRTIO_ID_SCSI) {
        struct Scsi_Host *shost = vd->priv;
        struct virtio_scsi *vscsi = shost_priv(shost);

        kdbxp("   virtio_scsi{} is:\n");
        kdbx_disp_virtio_scsi(vscsi);   /* drivers/scsi/virtio_scsi.c */
        kdbx_disp_scsi_host(shost);
    }
    return 0;
}

static int kdbx_display_vdev_cb(struct device *device, void *data)
{
    struct virtio_device *vd = dev_to_virtio(device);

    kdbxp("\t%p  %d(%s)  %s\n", vd, vd->id.device,
          kdbx_virtdev_to_str(vd->id.device), dev_name(&vd->dev));
    return 0;
#if 0
    struct virtio_driver *vdrvr = data;
    if ( vdrvr->id_table->device == VIRTIO_ID_BLOCK ) {
        kdbx_disp_virtio_blk(vd->priv);  /* drivers/block/virtio_blk.c */
    }
    if ( vdrvr->id_table->device == VIRTIO_ID_SCSI) {
        struct Scsi_Host *shost = vd->priv;
        struct virtio_scsi *vscsi = shost_priv(shost);

        kdbxp("   virtio_scsi{} is:\n");
        kdbx_disp_virtio_scsi(vscsi);   /* drivers/scsi/virtio_scsi.c */
        kdbx_disp_scsi_host(shost);
    }
    return kdbx_display_virtio_device(vd, vdrvr);
#endif
}

/* called for each device driver registered on the virtio bus */
static int kdbx_display_virtio_driver(struct virtio_driver *vdrvr)
{
    int i;
    const struct virtio_device_id *id_table;
    struct device_driver *drvr = &vdrvr->driver;

    kdbxp("virtio_driver: %p  probe: %s\n", vdrvr, kdbx_hostsym(drvr->probe));
    kdbxp("  device_driver: %p  nm: %s\n", drvr, drvr->name);
    for (id_table = vdrvr->id_table; id_table->device; id_table++) {
        kdbxp("  id_table: device: $%d (%s)\n", 
              id_table->device, kdbx_virtdev_to_str(id_table->device));
    }
    kdbxp("  devices for this driver: (virtio_dev* virt-dev(name) dev.name)\n");
    i = driver_for_each_device(drvr, NULL, vdrvr, kdbx_display_vdev_cb);
    kdbxp("----------------\n");

    return 0;
}

static kdbx_cpu_cmd_t kdb_usgf_viodev(void)
{
    kdbxp("display struct virtio_device{}\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_viodev(int argc, const char **argv, struct pt_regs *regs)
{
    struct virtio_device *vdp;

    if (argc < 2 || !kdb_str2ulong(argv[1], (ulong *)&vdp) )
        return kdb_usgf_viodev();

    kdbx_display_virtio_device(vdp);
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_viodrvr(void)
{
    kdbxp("display struct virtio_driver{}\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_viodrvr(int argc, const char **argv, struct pt_regs *regs)
{
    struct virtio_driver *vdp;

    if (argc < 2 || !kdb_str2ulong(argv[1], (ulong *)&vdp) )
        return kdb_usgf_viodrvr();

    kdbx_display_virtio_driver(vdp);
    return KDB_CPU_MAIN_KDB;
}

static void kdbx_display_virtio_pci_dev(struct virtio_pci_device *vpd)
{
    struct virtio_pci_common_cfg *pcg = vpd->common;

    kdbxp("virtio_pci_device: %p\n", vpd);
    kdbxp("  virtio_device: %p  pci_dev: %p\n", &vpd->vdev, vpd->pci_dev);
    kdbxp("  isr: %p  device: %p  notify_base: %p\n", vpd->isr, vpd->device,
          vpd->notify_base);
    kdbxp("  ioaddr: %p  msix_enabled: %d  intx_enabled: %d\n", vpd->ioaddr,
          vpd->msix_enabled, vpd->intx_enabled);
    kdbxp("  avail msix_vectors:$%d  msix_used_vectors:$%d per_vq_vectors:%d\n",
          vpd->msix_vectors, vpd->msix_used_vectors, vpd->per_vq_vectors);
    kdbxp("  **vqs: %p  *setup_vq(): %p\n", vpd->vqs, vpd->setup_vq);
    kdbxp("  virtio_pci_common_cfg: %p (to talk to backend)\n", pcg);
}

static kdbx_cpu_cmd_t kdb_usgf_viopcidev(void)
{
    kdbxp("viopcidev ptr: display struct virtio_pci_device{}\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_viopcidev(int argc, const char **argv, struct pt_regs *regs)
{
    struct virtio_pci_device *vpd;

    if (argc < 2 || !kdb_str2ulong(argv[1], (ulong *)&vpd) )
        return kdb_usgf_viopcidev();

    kdbx_display_virtio_pci_dev(vpd);
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_vbusdevs(void)
{
    kdbxp("list virtio devices on virtbus, and devices for those drivers\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_vbusdevs(int argc, const char **argv, struct pt_regs *regs)
{
    struct bus_type *virtio_bus = kdbx_ret_virtio_bus_addr();

    kdbxp("virtio_dev* virt-dev(name) dev.name:\n");
    bus_for_each_dev(virtio_bus, NULL, NULL, kdbx_display_vdev_cb);
    return KDB_CPU_MAIN_KDB;
}

static int kdbx_display_vdrvr_cb(struct device_driver *drvr, void *data)
{
    return kdbx_display_virtio_driver(drv_to_virtio(drvr));
}

static kdbx_cpu_cmd_t kdb_usgf_vbusdrvrs(void)
{
    kdbxp("list virtio drivers on virtbus, and devices for those drivers\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_vbusdrvrs(int argc, const char **argv, struct pt_regs *regs)
{
    struct bus_type *virtio_bus = kdbx_ret_virtio_bus_addr();

    bus_for_each_drv(virtio_bus, NULL, NULL, kdbx_display_vdrvr_cb);
    return KDB_CPU_MAIN_KDB;
}

static void kdbx_disp_bus_details(char *busnm, struct kvm_io_bus *iobus)
{
    int i;
    struct kvm_io_range *ior;
    void *rd, *wr;

    kdbxp("\n%s(%p): ioeventfd_count:%d dev_count:%d\n", 
          busnm, iobus, iobus->ioeventfd_count, iobus->dev_count);
    kdbxp(" kvm_io_range[]:\n");

    ior = iobus->range;
    for (i=0; i < iobus->dev_count; i++, ior++) {
        if ( ior->addr == 0 )
            continue;

        rd = ior->dev->ops->read;
        wr = ior->dev->ops->write;
        // dest = ior->dev->ops->destructor;
        kdbxp("    range:{addr:%lx len:%d}  iodev-ops:{rd:%s wr:%s}\n",
              ior->addr, ior->len, 
              rd ?  kdbx_hostsym(rd) : "NULL", 
              wr ? kdbx_hostsym(wr) : "NULL");
              // dest ? kdbx_hostsym(dest) : "0");
    }
}

/* include/linux/kvm_host.h: struct kvm_io_bus __rcu *buses[KVM_NR_BUSES] */
static void kvm_display_io_bus(struct kvm *kp)
{
    kdbxp("\n");
    kdbx_disp_bus_details("KVM_MMIO_BUS", kp->buses[KVM_MMIO_BUS]);
    kdbx_disp_bus_details("KVM_PIO_BUS", kp->buses[KVM_PIO_BUS]);
    kdbx_disp_bus_details("KVM_VIRTIO_CCW_NOTIFY_BUS", 
                           kp->buses[KVM_VIRTIO_CCW_NOTIFY_BUS]);
    kdbx_disp_bus_details("KVM_FAST_MMIO_BUS", kp->buses[KVM_FAST_MMIO_BUS]);
}

static kdbx_cpu_cmd_t kdb_usgf_kvmiodevs(void)
{
    kdbxp("kvmiodevs skvm-ptr: list io buses/devices for a VM\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_kvmiodevs(int argc, const char **argv, struct pt_regs *regs)
{
    struct kvm *kp = NULL;
    struct list_head *lp;

    if (argc > 1 && ((kp = kdbx_str2skvm(argv[1], 1)) == NULL) )
        return kdb_usgf_kvmiodevs();

    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list); /* container of*/

        kvm_disp_ioeventfds(kp);     /* virt/kvm/eventfd.c */
        kvm_display_io_bus(kp);
        kdbxp("\n");
    }
    return KDB_CPU_MAIN_KDB;
}

static void kdb_display_kvm_struct(struct kvm *kp)
{
    int i;
    struct kvm_memslots *km;
    struct kvm_arch *ka;
    struct kvm_vcpu *vp;
    struct task_struct *tp;

    kdbxp("struct kvm %p:  online_vcpus:%d  last_boosted:%d  VCPUs:\n", 
          kp, kp->online_vcpus.counter, kp->last_boosted_vcpu);

    for (i = 0; i < KVM_MAX_VCPUS; i++) {
        if ( (vp = kp->vcpus[i]) == NULL )
            continue;

        tp = pid_task(vp->pid, PIDTYPE_PID);
        kdbxp("         %p  vcpu_id: %d  pid:%d  tgid:%d\n", vp, vp->vcpu_id, 
              tp ? tp->pid : -1, tp ? tp->tgid : -1);
    }
    kdbxp("\n");
    kdbxp("  users_count: %d &kvm_vm_stat:%p\n", kp->users_count, &kp->stat);

    ka = &kp->arch;
    kdbxp("  kvm arch: n_used_mmu_pages:%x requested:%x max:%x\n",
          ka->n_used_mmu_pages, ka->n_requested_mmu_pages, ka->n_max_mmu_pages);
#if 0
/* moved to vmx.c in kvm_vmx in 4.14.35-1831. grrr */
    kdbxp("      ept_id_pg_done:%d ept_identity_map_addr:%p\n",
          !!ka->ept_identity_pagetable_done, ka->ept_identity_map_addr);
    kdbxp("      apic_ap_done:%d irq_sbitmap:%016lx\n", 
          !!ka->ept_identity_pagetable_done, ka->irq_sources_bitmap);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
    km = kp->memslots;
#else
    km = kp->memslots[0];
#endif
    kdbxp("\n");
    kdbxp("  memslots: %p generation:%x\n", km->memslots[0], km->generation);
    #define fs "    "
    for (i=0; i < KVM_MEM_SLOTS_NUM; i++) {
        struct kvm_memory_slot *ks = &km->memslots[i];

        if (ks->npages == 0)
            continue;
        kdbxp("%s[%d]: base_gfn:%p npages:%x\n",fs,i,ks->base_gfn, ks->npages);
        kdbxp("%s     uaddr:%016lx flags:%x id:%hx\n", fs, ks->userspace_addr,
              ks->flags, ks->id);
    }
    #undef fs
}

static kdbx_cpu_cmd_t kdb_usgf_skvm(void)
{
    kdbxp("skvm [ptr]: one or all kvm structs\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_skvm(int argc, const char **argv, struct pt_regs *regs)
{
    struct list_head *lp;
    struct kvm *argkp = NULL;   /* struct kvm in include/linux/kvm_host.h */

    if ( argc > 1 ) {
        if ( (argkp = kdbx_str2skvm(argv[1], 1)) == NULL )
            return kdb_usgf_skvm();
    }
    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list); /* container of*/

        KDBGP1("argkp:%p kp:%p\n", argkp, kp);
        if (argkp == NULL || argkp == kp)
            kdb_display_kvm_struct(kp);

        kdbxp("\n");
    }
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_vms(void)
{
    kdbxp("vms: list all VMs\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_vms(int argc, const char **argv, struct pt_regs *regs)
{
    struct kvm_vcpu *vp;
    struct list_head *lp;
    struct task_struct *tp;
    kdbva_t addr;
    pid_t pid, tgid = 0;
    int i;

    kdbxp("vp vcpu-id state(0==KVM_MP_STATE_RUNNABLE) IP\n");
    list_for_each(lp, &vm_list) {
        struct kvm *kp = list_entry(lp, struct kvm, vm_list); /* container of*/

        for (i=0; i < KVM_MAX_VCPUS; i++) {
            if ( (vp = kp->vcpus[i]) == NULL )
                continue;

            tp = pid_task(vp->pid, PIDTYPE_PID);
            pid = tp ? tp->pid : -1;
            addr = (kdbva_t)vp->arch.regs[VCPU_REGS_RIP]; /* always saved */

            if ( tgid == 0 )
                tgid = tp->tgid;
            if ( tgid && tgid != -1 ) {
                kdbxp("struct kvm:%p tgid:%d cpus:{created:%d online:%d}\n",
                      kp, tgid, kp->created_vcpus, kp->online_vcpus);
                tgid = -1;
            }
            kdbxp(" %lx %d %d %lx(%s)\n", vp, vp->vcpu_id, vp->arch.mp_state,
                  addr, kdbx_addr2sym(pid, addr, sbuf1, 0));
        }
        kdbxp("\n");
    }
    return KDB_CPU_MAIN_KDB;
}

/* toggle kdb debug trace level */
static kdbx_cpu_cmd_t kdb_usgf_kdbdbg(void)
{
    kdbxp("kdbdbg : trace info to debug kdb\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_kdbdbg(int argc, const char **argv, struct pt_regs *regs)
{
    kdbdbg = (kdbdbg==3) ? 0 : (kdbdbg+1);
    kdbxp("kdbdbg set to:%d\n", kdbdbg);
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_reboot(void)
{
    kdbxp("reboot: reboot system\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_reboot(int argc, const char **argv, struct pt_regs *regs)
{
    kdbxp("NOOOP.....\n");
    return KDB_CPU_MAIN_KDB;              /* not reached */
}


static kdbx_cpu_cmd_t kdb_usgf_trcon(void)
{
    kdbxp("trcon: turn user added kdb tracing on\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_trcon(int argc, const char **argv, struct pt_regs *regs)
{
    kdbx_trcon = 1;
    kdbxp("kdb tracing is now on\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_trcoff(void)
{
    kdbxp("trcoff: turn user added kdb tracing off\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_trcoff(int argc, const char **argv, struct pt_regs *regs)
{
    kdbx_trcon = 0;
    kdbxp("kdb tracing is now off\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_trcz(void)
{
    kdbxp("trcz : zero entire trace buffer\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_trcz(int argc, const char **argv, struct pt_regs *regs)
{
    kdbx_trczero();
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_trcp(void)
{
    kdbxp("trcp : give hints to dump trace buffer via dw/dd command\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_trcp(int argc, const char **argv, struct pt_regs *regs)
{
    kdbx_trcp();
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t kdb_usgf_dtrcp(void)
{
    kdbxp("dtrcp : give hints to dump trace buffer via dw/dd command\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_dtrcp(int argc, const char **argv, struct pt_regs *regs)
{
    kdbg_trcp();
    return KDB_CPU_MAIN_KDB;
}

/* print some basic info, constants, etc.. */
static kdbx_cpu_cmd_t kdb_usgf_ioctls(void)
{
    kdbxp("ioctls : display kvm ioctl values..\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_ioctls(int argc, const char **argv, struct pt_regs *regs)
{
    /* sequential IOCTLs can be deduced, so just print beginings.. */

    kdbxp("KVM_GET_API_VERSION: \t%08x\n", KVM_GET_API_VERSION);
    kdbxp("KVM_CREATE_VM: \t\t%08x\n", KVM_CREATE_VM);
    kdbxp("KVM_GET_MSR_INDEX_LIST: %08x\n", KVM_GET_MSR_INDEX_LIST);
    kdbxp("KVM_CHECK_EXTENSION: \t%08x\n", KVM_CHECK_EXTENSION );

    kdbxp("KVM_SET_MEMORY_REGION: \t%08x\n", KVM_SET_MEMORY_REGION);
    kdbxp("KVM_CREATE_VCPU: \t%08x\n", KVM_CREATE_VCPU);
    kdbxp("KVM_GET_DIRTY_LOG: \t%08x\n", KVM_GET_DIRTY_LOG);

    kdbxp("KVM_CREATE_IRQCHIP: \t%08x\n", KVM_CREATE_IRQCHIP);
    kdbxp("KVM_IRQ_LINE: \t\t%08x\n", KVM_IRQ_LINE);

    kdbxp("KVM_ASSIGN_DEV_IRQ: \t%08x\n", KVM_ASSIGN_DEV_IRQ);
    kdbxp("KVM_REINJECT_CONTROL: \t%08x\n", KVM_REINJECT_CONTROL);
    kdbxp("KVM_SET_BOOT_CPU_ID: \t%08x\n", KVM_SET_BOOT_CPU_ID);

    kdbxp("KVM_RUN: \t\t%08x\n", KVM_RUN);
    kdbxp("KVM_GET_REGS: \t\t%08x\n", KVM_GET_REGS);
    kdbxp("KVM_SET_REGS: \t\t%08x\n", KVM_SET_REGS);

    kdbxp("KVM_SET_CPUID2: \t%08x\n", KVM_SET_CPUID2);
    kdbxp("KVM_GET_CPUID2: \t%08x\n", KVM_GET_CPUID2);

    kdbxp("KVM_SET_VCPU_EVENTS: \t%08x\n", KVM_SET_VCPU_EVENTS);
    kdbxp("KVM_GET_DEBUGREGS: \t%08x\n", KVM_GET_DEBUGREGS);

    kdbxp("KVM_GET_REG_LIST: \t%08x\n", KVM_GET_REG_LIST);

    return KDB_CPU_MAIN_KDB;
}

static void kdb_show_sched_info(void)
{
    kdbxp("PREEMPT_NEED_RESCHED: %08x\n", PREEMPT_NEED_RESCHED);
    kdbxp("PREEMPT_ENABLED: %08x\n", PREEMPT_ENABLED);
    kdbxp("PREEMPT_DISABLED: %08x\n", PREEMPT_DISABLED);

    kdbxp("PREEMPT_MASK: %08x\n", PREEMPT_MASK);
    kdbxp("SOFTIRQ_MASK: %08x\n", SOFTIRQ_MASK);
    kdbxp("HARDIRQ_MASK: %08x\n", HARDIRQ_MASK);
    kdbxp("NMI_MASK: %08x\n", NMI_MASK);

    kdbxp("PREEMPT_OFFSET: %08x\n", PREEMPT_OFFSET);
    kdbxp("SOFTIRQ_OFFSET: %08x\n", SOFTIRQ_OFFSET);
    kdbxp("HARDIRQ_OFFSET: %08x\n", HARDIRQ_OFFSET);
    kdbxp("NMI_OFFSET: %08x\n", NMI_OFFSET);
    kdbxp("SOFTIRQ_DISABLE_OFFSET: %08x\n", SOFTIRQ_DISABLE_OFFSET);

}

static void kdb_show_cpu_masks(void)
{
    int cpu;

    kdbxp("cpus possible:");
    for_each_cpu(cpu, cpu_possible_mask)
        kdbxp(" %d", cpu);

    kdbxp("\ncpus online:  ");
    for_each_cpu(cpu, cpu_online_mask)
        kdbxp(" %d", cpu);

    kdbxp("\ncpus present:");
    for_each_cpu(cpu, cpu_present_mask)
        kdbxp(" %d", cpu);

    kdbxp("\ncpus active:  ");
    for_each_cpu(cpu, cpu_active_mask)
        kdbxp(" %d", cpu);
    kdbxp("\n");
}

/* print some basic info, constants, etc.. */
static kdbx_cpu_cmd_t kdb_usgf_info(void)
{
    kdbxp("info : display basic info, constants, etc..\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_info(int argc, const char **argv, struct pt_regs *regs)
{
    int cpu;
    struct cpuinfo_x86 *bcdp;
    struct setup_header *hdr = &boot_params.hdr;

    kdbxp("Version: %04d kernel_version:%04d\n", hdr->version, 
         hdr->kernel_version);

    bcdp = &boot_cpu_data;
    kdbxp("boot CPU data: (all decimal)");
        if (bcdp->x86_vendor == X86_VENDOR_AMD)
            kdbxp(" AMD");
        else
            kdbxp(" INTEL");
        kdbxp(" family:%d model:%d\n", bcdp->x86, bcdp->x86_model);
        kdbxp("   vendor_id:%s model_id:%s\n", bcdp->x86_vendor_id,
             bcdp->x86_model_id);
        kdbxp("   cpuidlvl:%d cache:sz:%d align:%d\n", bcdp->cpuid_level,
             bcdp->x86_cache_size, bcdp->x86_cache_alignment);
        kdbxp("     ");
    kdbxp("\n");
    kdbxp("_stext: "KDBFL"\t_etext: "KDBFL"\n", _stext, _etext);
    kdbxp("_sinittext: "KDBFL"\t_einittext: "KDBFL"\n", _sinittext, _einittext);

    kdbxp("cpu: cpu_to_apicid/apic-apicid/ (dec)\n");
    for_each_online_cpu(cpu) {
        // struct cpuinfo_x86 *c = &cpu_data(cpu);
        kdbxp("  %d: %d/%d\n", cpu, per_cpu(x86_cpu_to_apicid, cpu),
              apic->cpu_present_to_apicid(cpu));
    }
    kdb_show_cpu_masks();
    kdb_show_sched_info();

    return KDB_CPU_MAIN_KDB;
}

/* show current task info */
void kdbx_show_cur(struct pt_regs *regs)
{
    struct vmcs *vmcsp, *vmxap;
    int guest_mode = kdbx_guest_mode(regs);
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(current->pid, 0);

    kdbxp("[%d][%c]current(ts):%p  pid:%d  %s  preempt_cnt:%x\n",
          smp_processor_id(), guest_mode ? 'G' : 'H', current, current->pid, 
          current->comm, raw_cpu_read_4(__preempt_count));
#if 0
    kdbxp("   in_irq:%x softirq:%x intrupt:%x softsrv:%x in_task:%x\n",
          in_irq(), in_softirq(), in_interrupt(), in_softirq(), in_task());

#endif
    if ( vp ) {
        kdbx_ret_curr_vcpu_info(&vp, &vmcsp, &vmxap);
        kdbxp("   vcpu: %p vmcs: %p vmxa: %p\n", vp, vmcsp, vmxap);
    }
}

static kdbx_cpu_cmd_t kdb_usgf_cur(void)
{
    kdbxp("cur [all]: display current info for current or all cpus \n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_cur(int argc, const char **argv, struct pt_regs *regs)
{
    int cpu, ccpu = smp_processor_id();

    if ( argc > 1 && strcmp(argv[1], "all") )
        return kdb_usgf_cur();

    if (argc == 1) {
        kdbx_show_cur(regs);
    } else {
        for_each_online_cpu(cpu) {
            if (cpu == ccpu) {
                kdbx_show_cur(regs);
            } else {
                if (kdbx_cpu_cmd[cpu] != KDB_CPU_PAUSE)   /* hung cpu */
                    continue;
                kdbx_cpu_cmd[cpu] = KDB_CPU_SHOW_CUR;
                while (kdbx_cpu_cmd[cpu] == KDB_CPU_SHOW_CUR);
            }
        }
    }
    return KDB_CPU_MAIN_KDB;
}

#define KDBX_MAX_VHOST_SAV 256
struct kdbx_vhostdevs_sav {
    struct vhost_dev *vhdev;
    char *dev_type;  /* char * : vhost_scsi, vsock, net, test */
};
struct kdbx_vhostdevs_sav vhost_devs[KDBX_MAX_VHOST_SAV];
void kdbx_sav_vhost_dev(struct vhost_dev *dev, char *type)
{
    int i;

    for (i=0; i < KDBX_MAX_VHOST_SAV; i++) {
        struct kdbx_vhostdevs_sav *p = &vhost_devs[i];

        if (p->vhdev == NULL) {
            p->vhdev = dev;
            p->dev_type = type;
            break;
        }
    }
    if ( i >= KDBX_MAX_VHOST_SAV )
        kdbxp(">>>>>>>>> vhost_devs array FULL!!!|\n");
}
EXPORT_SYMBOL_GPL(kdbx_sav_vhost_dev);

static kdbx_cpu_cmd_t kdb_usgf_vhostdevs(void)
{
    kdbxp("vhostdevs: list all vhost devices\n");
    kdbxp("  make sure: vhost net/scsi mods compiled with kdbx\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_vhostdevs(int argc, const char **argv, struct pt_regs *regs)
{
    int i;

    kdbxp("  (make sure: vhost net/scsi mods compiled with kdbx)\n");
    for (i=0; i < KDBX_MAX_VHOST_SAV; i++) {
        struct kdbx_vhostdevs_sav *p = &vhost_devs[i];

        if (p->vhdev == NULL)
            continue;
        kdbxp("dev:%p type:%s worker:(%d)%s\n", p->vhdev, p->dev_type,
              p->vhdev->worker->pid, p->vhdev->worker->comm);
    }
    return KDB_CPU_MAIN_KDB;
}

#if 0
static kdbx_cpu_cmd_t kdb_usgf_devices(void)
{
    kdbxp("devices: list all devices\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_devices(int argc, const char **argv, struct pt_regs *regs)
{
    // struct device *dev;  /* include/linux/device.h */
    kdbxp("kdbx: just browse thru /sys for all devices\n");
    return KDB_CPU_MAIN_KDB;
}
#endif

static kdbx_cpu_cmd_t kdb_usgf_bio(void)
{
    kdbxp("bio addr: display struct bio (include/linux/blk_types.h)\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_bio(int argc, const char **argv, struct pt_regs *regs)
{
    struct bio *bp;   /* include/linux/blk_types.h */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    struct block_device *bd;
#else
    struct gendisk *gd;                   /* include/linux/genhd.h */
#endif

    if (argc < 2)
        return kdb_usgf_bio();

    if (!kdb_str2addr(argv[1], (kdbva_t *)&bp, 0)) {
        kdbxp("Invalid addr: %lx\n", bp);
        return KDB_CPU_MAIN_KDB;
    }
    kdbxp("bio: %p\n", bp);
    kdbxp("  bi_sector: %lx  bi_next:%p\n", bp->bi_iter.bi_sector, bp->bi_next);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
    kdbxp("  bi_flags: %lx  bi_rw:%lx  op_is_flush:%d\n", bp->bi_flags,
          bp->bi_rw, op_is_flush(bp->bi_opf));
#else
    kdbxp("  bi_flags: %lx  bi_opf(rw):%lx  op_is: flush:%d  sync:%d\n",
          bp->bi_flags, bp->bi_opf, op_is_flush(bp->bi_opf),
          op_is_sync(bp->bi_opf));
#endif
    kdbxp("  bi_vcnt:%hx  bi_idx:%hd  bi_size:%x  bi_phys_segments:%x\n",
          bp->bi_vcnt, bp->bi_iter.bi_idx, bp->bi_iter.bi_size, 
          bp->bi_phys_segments);
    kdbxp("  bi_end_io:%p  bi_private:%p\n", bp->bi_end_io, bp->bi_private);
    kdbxp("\n"); 
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    bd = bp->bi_bdev;
    kdbxp("  block device: bi_bdev:%p\n", bd);
    kdbxp("    bd_dev:%lx request_queue:%p\n", bd->bd_dev, bd->bd_queue);
#else
    gd = bp->bi_disk;
    kdbxp("    gendisk: %p  major:$%d  first_minor:$%d  minors:$%d\n", 
          gd, gd->major, gd->first_minor, gd->minors);
    kdbxp("    devnode:%p  disk_name: %s\n", gd->devnode, gd->disk_name);
    kdbxp("    request_queue: %p  private_data:%p\n", gd->queue, 
          gd->private_data);
#endif

    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_req(void)
{
    kdbxp("req addr: display struct request for block device\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_req(int argc, const char **argv, struct pt_regs *regs)
{
    struct request *req;      /* include/linux/blkdev.h */

    if (argc < 2)
        return kdb_usgf_req();

    if (!kdb_str2addr(argv[1], (kdbva_t *)&req, 0)) {
        kdbxp("Invalid addr: %lx\n", req);
        return KDB_CPU_MAIN_KDB;
    }
    kdbxp("request: %p  reqq: %p  cpu: %d\n", req, req->q, req->cpu);
    kdbxp("  cmd_flags(srch req_opf): %x  rq_flags(RQF_QUEUED): %x\n",
          req->cmd_flags, req->rq_flags);
    kdbxp("  bio: %p  gendisk: %p\n", req->bio, req->rq_disk);
    kdbxp("  hd_struct: %p  end_io: %s\n", req->part,kdbx_hostsym(req->end_io));
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_reqq(void)
{
    kdbxp("reqq addr: display struct request_queue for block device\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_reqq(int argc, const char **argv, struct pt_regs *regs)
{
    struct request_queue *rq;      /* include/linux/blkdev.h */
    char *bd_name;

    if (argc < 2)
        return kdb_usgf_reqq();

    if (!kdb_str2addr(argv[1], (kdbva_t *)&rq, 0)) {
        kdbxp("Invalid addr: %lx\n", rq);
        return KDB_CPU_MAIN_KDB;
    }
    kdbxp("request queue: %p\n", rq);
    kdbxp("  request_fn: %s  make_request_fn: %s\n", 
          kdbx_hostsym(rq->request_fn), kdbx_hostsym(rq->make_request_fn)); 
    kdbxp("  softirq_done_fn: %s  prep_rq_fn: %s\n", 
          kdbx_hostsym(rq->softirq_done_fn), kdbx_hostsym(rq->prep_rq_fn)); 
    kdbxp("  elevator: %p  blk_mq_ops: %p\n", rq->elevator, rq->mq_ops);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    bd_name = (char *)rq->backing_dev_info->name;
#else
    bd_name = rq->backing_dev_info.name;
#endif

    kdbxp("  nr_queues:%x  nr_hw_queues:%x", rq->nr_queues, rq->nr_hw_queues);
    kdbxp("    end_sector:%lx  backing_dev name:%s\n", rq->end_sector, bd_name);
    kdbxp("  nr_requests:%lx  request_fn_active:%d", rq->nr_requests,
          rq->request_fn_active);
    kdbxp("    queuedata: %p\n", rq->queuedata);

    return KDB_CPU_MAIN_KDB;
}

static void kdbx_disp_block_device(struct block_device *bdev)
{
    if ( !bdev )
        return;

    kdbxp("block_device: %p  major: %d  minor: %d\n", bdev,
          MAJOR(bdev->bd_dev),  MINOR(bdev->bd_dev)); 
    kdbxp("  openers: %d  inode: %p  block_size: %d\n", bdev->bd_openers,
          bdev->bd_inode, bdev->bd_block_size);
    kdbxp("  partno: %d  part_count: %d invalidated: %d\n", bdev->bd_partno,
          bdev->bd_part_count, bdev->bd_invalidated);
    kdbxp("  hd_struct/part: %p  gendisk: %p (%s)\n", bdev->bd_part,
          bdev->bd_disk, bdev->bd_disk ? bdev->bd_disk->disk_name : "");
    kdbxp("  request_queue: %p  private: %lx\n", bdev->bd_queue,
          bdev->bd_private);

    if ( !bdev->bd_bdi )
        return;
    kdbxp("  backing_dev_info:%p {.name:%s  .device: %p}\n\n", 
         bdev->bd_bdi, bdev->bd_bdi->name, bdev->bd_bdi->dev);
}

static kdbx_cpu_cmd_t kdb_usgf_blkdevs(void)
{
    kdbxp("blkdevs: list block devices\n");
    return KDB_CPU_MAIN_KDB;
}

/* fs/block_dev.c: iterate_bdevs() takes many spin locks, so avoid that */
static kdbx_cpu_cmd_t kdb_cmdf_blkdevs(int argc, const char **argv, 
                                       struct pt_regs *regs)
{
    struct inode *inode;

    kdbxp("maj/minor openers block_size partno part_count inval DECIMAL\n");
    list_for_each_entry(inode, &blockdev_superblock->s_inodes, i_sb_list) {
        if (inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW) )
            continue;
        kdbx_disp_block_device(I_BDEV(inode));
    }
    return KDB_CPU_MAIN_KDB;
    
}

/* see genhd_device_init: class_register(&block_class) */
static kdbx_cpu_cmd_t kdb_usgf_disks(void)
{
    kdbxp("disks: list disk/gendisk devices\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t kdb_cmdf_disks(int argc, const char **argv, 
                                       struct pt_regs *regs)
{
    int i;
    struct hd_struct *part;      /* disk partition: linux/genhd.h */
    struct class_dev_iter iter;
    struct device *dev;          /* include/linux/device.h */

    kdbxp("maj/min, start_sect, nr_sects... all DECIMAL\n");
    class_dev_iter_init(&iter, &block_class, NULL, NULL);
    while ((dev = class_dev_iter_next(&iter))) {
        struct gendisk *gd = dev_to_disk(dev); /*  include/linux/genhd.h */
        const struct block_device_operations *fops = gd ? gd->fops : NULL;

        // kdbx_disp_struct_device(dev, 0); 
        kdbxp("device: name:%s  device_type name:%s\n", dev_name(dev),
              dev->type ? dev->type->name : "\0"); 

        /* disk_type has name of "disk". gendisk has junk if not disk */
        if ( strcmp(dev->type->name, "disk") || !gd || gd->major == 0 ) {
            kdbxp("\n");
            continue;
        }
        kdbxp("  gendisk(%p): disknm:%s major: %d  first minor: %d\n",
              gd, gd->disk_name, gd->major, gd->first_minor);
        kdbxp("    request_queue: %p  private_data: %p sync_io: %d\n",
              gd->queue, gd->private_data, gd->sync_io.counter);
        if ( !fops )
            continue;

        /* kdbx_hostsym uses static buf, hence only one per kdbxp */
        kdbxp("    dev ops: owner:%s  open: %s  ioctl:%s",
              fops->owner ? fops->owner->name : "", 
              kdbx_hostsym(fops->open), kdbx_hostsym(fops->ioctl));
        kdbxp("  rw_page: %s\n", kdbx_hostsym(fops->rw_page));

        part = &gd->part0;
        kdbxp("    part0: start_sect: %d  nr_sects: %d\n",
              part->start_sect, part->nr_sects);
        if ( gd->part_tbl == NULL || gd->part_tbl->len == 0 ) {
            kdbxp("\n");
            continue;
        }
        /* entry zero points to part0 above */
        for (i=0; i < gd->part_tbl->len; i++ ) {
            part = gd->part_tbl->part[i];
            kdbxp("    partition %d: start_sect: %d  nr_sects: %d\n",
                  i, part->start_sect, part->nr_sects);
        }
        kdbxp("\n");
    }
    class_dev_iter_exit(&iter);

    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_netdevs(void)
{
    kdbxp("netdevs: list network devices (struct net_device)\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_netdevs(int argc, const char **argv, struct pt_regs *regs)
{
    struct net_device *nd;      /* include/linux/netdevice.h */

    for (nd = first_net_device(&init_net); nd; nd = next_net_device(nd))
        kdbxp("%p: %s\n", nd, nd->name);

    return KDB_CPU_MAIN_KDB;
}

static void kdb_print_netdev(struct net_device *nd)
{
    struct net_device_stats *st = &nd->stats;

    kdbxp("device: %p name: %s\n", nd, nd->name); 
    kdbxp("active features: %lx rx_dropped: %lx\n",nd->features,nd->rx_dropped);
    kdbxp("struct net_device_stats:\n");
    kdbxp("  rx_errs: %lx tx_errs: %lx\n", st->rx_errors, st->tx_errors);
    kdbxp("  rx_dropped: %lx tx_dropped: %lx\n", st->rx_dropped,st->tx_dropped);
    kdbxp("  rx errs: len:%lx ovr:%lx crc:%lx frame:%lx fifo:%lx missed:%lx\n",
          st->rx_length_errors,  st->rx_over_errors, st->rx_crc_errors, 
          st->rx_frame_errors, st->rx_fifo_errors, st->rx_missed_errors);
    kdbxp("  tx errs: aborted:%lx carr:%lx fifo:%lx hbt:%lx window:%lx\n",
          st->tx_aborted_errors, st->tx_carrier_errors, st->tx_fifo_errors,
          st->tx_heartbeat_errors, st->tx_window_errors);
    kdbxp("  collisions: %lx multicast: %lx rx_comp: %lx tx: %lx\n",
          st->collisions, st->multicast, st->rx_compressed, st->tx_compressed);
    kdbxp("\n");
}

static kdbx_cpu_cmd_t kdb_usgf_netdev(void)
{
    kdbxp("netdev ptr: net_device detail. run netdevs to see list\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_netdev(int argc, const char **argv, struct pt_regs *regs)
{
    struct net_device *nd, *tp;      /* include/linux/netdevice.h */

    if (argc <= 1 || !kdb_str2ulong(argv[1], (ulong *)&nd) )
    {
        return kdb_usgf_netdev();
    }

    for (tp = first_net_device(&init_net); tp; tp = next_net_device(tp))
        if (tp == nd)
            break;

    if ( tp == NULL ) {
        kdbxp("net device %p not found\n", nd);
        return KDB_CPU_MAIN_KDB;
    }
    kdb_print_netdev(nd);

    return KDB_CPU_MAIN_KDB;
}

static void kdb_display_socket(struct sock *sk)
{
    if (sk == NULL) 
        return;

    kdbxp("    sock cmn: num:%x/$%d daddr: %x (local)rcv_addr:%x\n",
          sk->sk_num, sk->sk_num, sk->sk_daddr, sk->sk_rcv_saddr);
    kdbxp("    drops: %x rcvbufsz:%x socket:%p\n", 
          atomic_read(&sk->sk_drops), sk->sk_rcvbuf, sk->sk_socket);
    kdbxp("    sk_err: %x sk_err_soft:%x\n", sk->sk_err, sk->sk_err_soft);
}

static kdbx_cpu_cmd_t kdb_usgf_socket(void)
{
    kdbxp("socket ptr: print some socket details\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_socket(int argc, const char **argv, struct pt_regs *regs)
{
    struct sock *sk;       /* include/net/sock.h  */

    if (argc <= 1 || !kdb_str2ulong(argv[1], (ulong *)&sk) )
    {
        return kdb_usgf_socket();
    }
    kdb_display_socket(sk);
    return KDB_CPU_MAIN_KDB;
}

static void kdbx_hex_to_ip(uint hexip, char *buf, int len)
{
    int v1, v2, v3, v4;

    memset(buf, 0, len);
    v1 = hexip & 0xFF;
    v2 = (hexip & 0xFF00) >> 8;
    v3 = (hexip & 0xFF0000) >> 16;
    v4 = (hexip & 0xFF000000) >> 24;
    sprintf(buf, "%d.%d.%d.%d\n", v1, v2, v3, v4);
}

char *kdb_skb_csum_str(uint ip_summed)
{
    if (ip_summed == CHECKSUM_NONE)
        return " CHECKSUM_NONE ";
    else if (ip_summed == CHECKSUM_UNNECESSARY)
        return " CHECKSUM_UNNECESSARY ";
    else if (ip_summed == CHECKSUM_COMPLETE)
        return " CHECKSUM_COMPLETE ";
    else if (ip_summed == CHECKSUM_PARTIAL)
        return " CHECKSUM_PARTIAL ";
    else 
        return " unknown ";
}

void kdb_display_skb(struct sk_buff *skb)
{
    struct sock *sk;       /* include/net/sock.h  */
    struct tcphdr *tcphdr;
    struct iphdr *iphdr;

    kdbxp("skb: %p (FIXME: check for valid skb ptr)\n", skb);
    kdbxp("  net_device: %p  name: %s\n", skb->dev, skb->dev->name);

    sk = skb->sk;
    kdbxp("  socket:%p  head:%p  data:%p\n", sk, skb->head, skb->data);
    kdb_display_socket(sk);

    kdbxp("  len: %x  data_len: %x  ", skb->len, skb->data_len);
    kdbxp("  mac_len: %hx  hdr_len: %hx  nohdr:%d\n", skb->mac_len, 
          skb->hdr_len, skb->nohdr);
    kdbxp("  protocol: %4x  vlan_proto: %hx  vlan_tci: %hx\n",
          skb->protocol, skb->vlan_proto, skb->vlan_tci);
    kdbxp("  queue_mapping: %hx  encapsulation: %d csum:%d %s\n", 
          skb->queue_mapping, skb->encapsulation, skb->ip_summed,
          kdb_skb_csum_str(skb->ip_summed));

    tcphdr = tcp_hdr(skb);
    kdbxp("  tcp/transport_header: %4hx %p  hdrlen:%d\n", skb->transport_header,
          tcphdr, tcp_hdrlen(skb));
    if (tcphdr) {
        kdbxp("    src: %4hx  dest:%4hx  window:%4hx  len:%x\n", tcphdr->source,
              tcphdr->dest, tcphdr->window, tcp_hdrlen(skb));
    }
    iphdr = ip_hdr(skb);
    kdbxp("  ip/network_header: %4hx %p   len:%d\n", skb->network_header, 
          iphdr, iphdr->tot_len);
    if (iphdr) {
        char b1[16], b2[16]; 
        uint saddr = iphdr->saddr, daddr = iphdr->daddr;
        
        kdbx_hex_to_ip(saddr, b1, sizeof(b1)); 
        kdbx_hex_to_ip(daddr, b2, sizeof(b2));
        kdbxp("    saddr: %8x/%s  daddr: %8x/%s\n", saddr, b1, daddr, b2);
    }
    kdbxp("  mac_header: %4hx %p\n", skb->mac_header, skb_mac_header(skb));
    kdbxp("  inner headers: protocol: %4hx  transport:%4hx  network:%4hx"
          "  mac: %4hx\n", skb->inner_protocol, skb->inner_transport_header,
          skb->inner_network_header, skb->inner_mac_header);
}

static kdbx_cpu_cmd_t kdb_usgf_skb(void)
{
    kdbxp("skb ptr: print some skb details\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_skb(int argc, const char **argv, struct pt_regs *regs)
{
    struct sk_buff *skb;        /* linux/skbuff.h */

    if (argc <= 1 || !kdb_str2ulong(argv[1], (ulong *)&skb) )
    {
        return kdb_usgf_skb();
    }
    kdb_display_skb(skb);
    return KDB_CPU_MAIN_KDB;
}

#ifdef __KDBX_SUPPORT_FOR_HYPERV  /* also used in drivers/net/hyperv/netvsc.c */
#include "../drivers/net/hyperv/hyperv_net.h"

static void kdb_display_vmbus_channel(struct vmbus_channel *vb)
{
    struct hv_ring_buffer_info *rb;
    struct hv_ring_buffer *rr;

    kdbxp("vmbus_channel: %p  state: %d ringbuffer_gpadlhandle: %x\n", 
          vb, vb->state, vb->ringbuffer_gpadlhandle);
    kdbxp("  ringbuffer_pagecount: %x batched_reading: %d"
          " is_dedicated_interrupt: %d\n", vb->ringbuffer_pagecount,
          vb->batched_reading, vb->is_dedicated_interrupt);
    kdbxp("  target_vp: %x target_cpu: %x\n", vb->target_vp, vb->target_cpu);

    rb = &vb->outbound;
    rr = rb->ring_buffer;
    kdbxp("  outbound ringbuffer: sz: %x datasize: %x startoffs: %x\n",
          rb->ring_size, rb->ring_datasize, rb->ring_data_startoffset);
    kdbxp("    hv_ring_buffer: %p\n", rr);
    kdbxp("    write_index: %x read_index: %x\n", rr->write_index, 
          rr->read_index);
    kdbxp("    interrupt_mask: %x pending_send_sz: %x\n", rr->interrupt_mask, 
          rr->pending_send_sz);

    rb = &vb->inbound;
    rr = rb->ring_buffer;
    kdbxp("  inbound ringbuffer: sz: %x datasize: %x startoffs: %x\n",
          rb->ring_size, rb->ring_datasize, rb->ring_data_startoffset);
    kdbxp("    write_index: %x read_index: %x\n", rr->write_index, 
          rr->read_index);
    kdbxp("    interrupt_mask: %x pending_send_sz: %x\n", rr->interrupt_mask, 
          rr->pending_send_sz);
}

static kdbx_cpu_cmd_t kdb_usgf_vmbusc(void)
{
    kdbxp("vmbusc ptr: print few struct vmbus_channel fields\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_vmbusc(int argc, const char **argv, struct pt_regs *regs)
{
    struct vmbus_channel *vb;

    if (argc <= 1 || !kdb_str2ulong(argv[1], (ulong *)&vb) ) {
        return kdb_usgf_vmbusc();
    }

    kdb_display_vmbus_channel(vb);

    return KDB_CPU_MAIN_KDB;
}

struct netvsc_device *kdbx_netvsca[64];

void kdbx_add_netvsc(struct netvsc_device *nvsc)
{
    int i;

    for (i=0; i < 64; i++) {
        if ( kdbx_netvsca[i] == NULL ) {
            kdbx_netvsca[i] = nvsc;
            return;
        }
    }
    kdbxp("kdbx_add_netvsc: Unable to add netvsc ptr %p\n", nvsc);
}

static void kdb_print_netvsc_info(void)
{
    int i;
    struct netvsc_device *p;

    kdbxp("netvsc-ptr   netdev-ptr  name\n");
    for (i=0; i < 64; i++) {
        if ( (p=kdbx_netvsca[i]) ) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
            kdbxp("%p  %p  %s\n", p, p->ndev, p->ndev->name);
#else
            kdbxp("%p \n", p);
#endif
        }
    }
}

void kdb_display_netvsc_info(struct netvsc_device *nv)
{
    int i, loopmax;

    if (nv == NULL)
        return;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
    kdbxp("netvsc device: %p  nvsp_version: %x net_dev: %p\n", 
          nv, nv->nvsp_version, nv->ndev);
    kdbxp("  hv_device: %p hv_device.channel: %p\n", nv->dev, nv->dev->channel);
#endif

    kdbxp("  num_outstanding_sends: %x ring_size: %x pages (bytes: %x)\n",
          nv->num_outstanding_sends, nv->ring_size, nv->ring_size * PAGE_SIZE);
    kdbxp("  recv _buf_size: %x _buf_gpadl_handle: %x _section_cnt: %x\n",
          nv->recv_buf_size, nv->recv_buf_gpadl_handle, nv->recv_section_cnt);
    kdbxp("  send _buf_size: %x _buf_gpadl_handle: %x _cnt: %x _size: %x\n",
          nv->send_buf_size, nv->send_buf_gpadl_handle, nv->send_section_cnt,
          nv->send_section_size);
    kdbxp("  num_chn: %x map_words: %x\n", nv->num_chn, nv->map_words);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
    loopmax = NR_CPUS;
#else
    loopmax = VRSS_CHANNEL_MAX;
#endif

    kdbxp("  \nvmbus_channel[NR_CPUS/VRSS_CHANNEL_MAX]:\n");
    for (i=0; i < loopmax; i++) {
        if (nv->chn_table[i])
            kdb_display_vmbus_channel(nv->chn_table[i]);
            // kdbxp(" %d: %p \n", i, nv->chn_table[i]);
    }
    kdbxp("\n");

    kdbxp("  queue_sends counts[NR_CPUS]:\n");
    for (i=0; i < loopmax; i++) {
        if (nv->queue_sends[i].counter)
            kdbxp(" %d: %p \n", i, nv->queue_sends[i].counter);
    }
    kdbxp("\n");
}

static kdbx_cpu_cmd_t kdb_usgf_netvsc(void)
{
    kdbxp("netvsc [ptr]: print few struct netvsc_device fields\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_netvsc(int argc, const char **argv, struct pt_regs *regs)
{
    struct netvsc_device *nv;

    if ( argc <= 1 ) {
        kdb_print_netvsc_info();
        return KDB_CPU_MAIN_KDB;
    }

    if ( !kdb_str2ulong(argv[1], (ulong *)&nv) ) {
        return kdb_usgf_netvsc();
    }
    kdb_display_netvsc_info(nv);
    return KDB_CPU_MAIN_KDB;
}
#endif /*  __KDBX_SUPPORT_FOR_HYPERV */

/* stub to quickly and easily add a new command */
static kdbx_cpu_cmd_t kdb_usgf_usr1(void)
{
    kdbxp("usr1: add any arbitrary cmd using this in kdb_cmds.c\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t
kdb_cmdf_usr1(int argc, const char **argv, struct pt_regs *regs)
{
    ulong *p = (ulong *)0xDEAD;

    mukchk(*p);
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_uart(void)
{
    kdbxp("uart: dump uart\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_uart(int argc, const char **argv, struct pt_regs *regs)
{
    kdbx_dump_uart();
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_bl(void)
{
    kdbxp("bl bitmap: print list for given bitmap\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_bl(int argc, const char **argv, struct pt_regs *regs)
{
    ulong bm;

    if ( argc < 2 )
        return kdb_usgf_bl();

    if ( !kdb_str2ulong(argv[1], &bm) || bm == 0 || bm == (ulong)-1 ) {
        kdbxp("invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    kdbxp("%lx: ", bm);
    kdbx_prnt_cpumask((struct cpumask *)&bm, "\n");
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_cons(void)
{
    kdbxp("cons: show active consoles\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_cons(int argc, const char **argv, struct pt_regs *regs)
{
    struct console *c;
    int kdbx_tty_line;
    struct tty_driver *kdbx_tty_driver;

    kdbxp("Consoles are:\n");
    for_each_console(c) {
        kdbxp("Console: %s index: %d\n", c->name, c->index);
        kdbxp("\trd:%p  wr:%p\n", c->read, c->write);
        kdbxp("\ttty_driver:%p  setup:%p\n", c->device, c->setup);
        kdbxp("\n");
    }

    kdbx_tty_driver = tty_find_polling_driver("ttyS0", &kdbx_tty_line);
    kdbxp("ttyS0: kdbx_tty_driver->ops->poll_get_char is: %p\n",
          kdbx_tty_driver->ops->poll_get_char);
    // kdbx_dump_uart();

    return KDB_CPU_MAIN_KDB;
}


static kdbx_cpu_cmd_t kdb_usgf_kdbcur(void)
{
    kdbxp("kdbcur: show debug info currently in kdb\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_kdbcur(int argc, const char **argv, struct pt_regs *regs)
{
    int cpu;
    ulong rflags;

    kdbxp("[%d]%s  regs:%016lx", smp_processor_id(),
          kdbx_guest_mode(regs) ? "guest_mode" : "host_mode",
          regs);

    asm volatile("pushfq;\n\t"
                 "pop %[rflags]\n\t"
                 :[rflags]"=&r"(rflags)
                 ::);
    kdbxp("  rflags:%lx %s\n", rflags, 
          rflags & X86_EFLAGS_IF ? "enabled" : "disabled");
#if 0
    asm volatile("pushl %%cs;\n\t"
                 "pop %[cs]\n\t"
                 :[cs]"=&r"(cs)
                 ::);
    kdbxp("  cs:%lx\n", cs);
#endif

    for_each_online_cpu(cpu) {
        kdbx_cpu_cmd_t cmd = kdbx_cpu_cmd[cpu];

        kdbxp("cpu:%d cmd:%d %s\n", cpu, cmd, kdb_cpu_cmd_str(cmd));
    }
    return KDB_CPU_MAIN_KDB;
}

static kdbx_cpu_cmd_t kdb_usgf_h(void)
{
    kdbxp("h: display all commands. See kdb/README for more info\n");
    return KDB_CPU_MAIN_KDB;
}
static kdbx_cpu_cmd_t
kdb_cmdf_h(int argc, const char **argv, struct pt_regs *regs)
{
    struct kdbxtab *tbp;

    kdbxp(" - ccpu is current cpu \n");
    kdbxp(" - following are always in decimal:\n");
    kdbxp("     cpu num, pid, tid, vcpu id\n");
    kdbxp(" - otherwise, almost all numbers are in hex (0x not needed)\n");
    kdbxp(" - output: $17 means decimal 17\n");
    kdbxp(" - earlykdb in grub line to break into kdb during boot\n");
    kdbxp(" - command ? will show the command usage\n");
    kdbxp("\n");

    for(tbp=kdb_cmd_tbl; tbp->kdb_cmd_usgf; tbp++)
        (*tbp->kdb_cmd_usgf)();
    return KDB_CPU_MAIN_KDB;
}

/* ===================== cmd table initialization ========================== */
void __init kdbx_init_cmdtab(void)
{
  static struct kdbxtab _kdb_cmd_table[] = {

    {"info", kdb_cmdf_info, kdb_usgf_info, 1, KDBX_REPEAT_NONE},
    {"mmu",   kdb_cmdf_mmu,   kdb_usgf_mmu,   1, KDBX_REPEAT_NONE},
    {"ioctls",kdb_cmdf_ioctls,   kdb_usgf_ioctls,   1, KDBX_REPEAT_NONE},
    {"cur",  kdb_cmdf_cur, kdb_usgf_cur, 1, KDBX_REPEAT_NONE},

    {"f",  kdb_cmdf_f,  kdb_usgf_f,  1, KDBX_REPEAT_NONE},

    {"dw",  kdb_cmdf_dw,  kdb_usgf_dw,  1, KDBX_REPEAT_NO_ARGS},
    {"dd",  kdb_cmdf_dd,  kdb_usgf_dd,  1, KDBX_REPEAT_NO_ARGS},
    {"dwm", kdb_cmdf_dwm, kdb_usgf_dwm, 1, KDBX_REPEAT_NO_ARGS},
    {"ddm", kdb_cmdf_ddm, kdb_usgf_ddm, 1, KDBX_REPEAT_NO_ARGS},
    {"dr",  kdb_cmdf_dr,  kdb_usgf_dr,  1, KDBX_REPEAT_NONE},

    {"dis", kdb_cmdf_dis,  kdb_usgf_dis,  1, KDBX_REPEAT_NO_ARGS},
    {"dism",kdb_cmdf_dism, kdb_usgf_dism, 1, KDBX_REPEAT_NO_ARGS},

    {"mw", kdb_cmdf_mw, kdb_usgf_mw, 1, KDBX_REPEAT_NONE},
    {"md", kdb_cmdf_md, kdb_usgf_md, 1, KDBX_REPEAT_NONE},
    {"mr", kdb_cmdf_mr, kdb_usgf_mr, 1, KDBX_REPEAT_NONE},

    {"bc", kdb_cmdf_bc, kdb_usgf_bc, 0, KDBX_REPEAT_NONE},
    {"bp", kdb_cmdf_bp, kdb_usgf_bp, 1, KDBX_REPEAT_NONE},
    {"btp", kdb_cmdf_btp, kdb_usgf_btp, 1, KDBX_REPEAT_NONE},

    {"wp", kdb_cmdf_wp, kdb_usgf_wp, 1, KDBX_REPEAT_NONE},
    {"wc", kdb_cmdf_wc, kdb_usgf_wc, 0, KDBX_REPEAT_NONE},

    {"ni", kdb_cmdf_ni, kdb_usgf_ni, 0, KDBX_REPEAT_NO_ARGS},
    {"ss", kdb_cmdf_ss, kdb_usgf_ss, 1, KDBX_REPEAT_NO_ARGS},
    {"ssb",kdb_cmdf_ssb,kdb_usgf_ssb,0, KDBX_REPEAT_NO_ARGS},
    {"go", kdb_cmdf_go, kdb_usgf_go, 0, KDBX_REPEAT_NONE},

    {"cpu",kdb_cmdf_cpu, kdb_usgf_cpu, 1, KDBX_REPEAT_NONE},
    {"nmi",kdb_cmdf_nmi, kdb_usgf_nmi, 1, KDBX_REPEAT_NONE},
    {"pcpu",kdb_cmdf_pcpu, kdb_usgf_pcpu, 1, KDBX_REPEAT_NONE},
    {"slk",kdb_cmdf_slk, kdb_usgf_slk, 1, KDBX_REPEAT_NONE},

    {"tl", kdb_cmdf_tl, kdb_usgf_tl, 1, KDBX_REPEAT_NONE},
    {"ts", kdb_cmdf_ts, kdb_usgf_ts, 1, KDBX_REPEAT_NONE},
    {"sched", kdb_cmdf_sched, kdb_usgf_sched, 1, KDBX_REPEAT_NONE},
    {"runq", kdb_cmdf_runq, kdb_usgf_runq, 1, KDBX_REPEAT_NONE},
    {"iommu", kdb_cmdf_iommu,   kdb_usgf_iommu,   1, KDBX_REPEAT_NONE},
    {"dmsr",  kdb_cmdf_dmsr,  kdb_usgf_dmsr, 1, KDBX_REPEAT_NONE},
    {"cpuid",  kdb_cmdf_cpuid,  kdb_usgf_cpuid, 1, KDBX_REPEAT_NONE},

    {"trq", kdb_cmdf_trq,  kdb_usgf_trq, 1, KDBX_REPEAT_NONE},
    {"dgdt", kdb_cmdf_dgdt,  kdb_usgf_dgdt, 1, KDBX_REPEAT_NONE},
    {"didt", kdb_cmdf_didt,  kdb_usgf_didt, 1, KDBX_REPEAT_NONE},
    {"apic", kdb_cmdf_apic,  kdb_usgf_apic, 1, KDBX_REPEAT_NONE},
    {"dirq", kdb_cmdf_dirq,  kdb_usgf_dirq, 1, KDBX_REPEAT_NONE},
    {"dpage", kdb_cmdf_dpage,  kdb_usgf_dpage, 1, KDBX_REPEAT_NONE},

    /* general kernel data structures */
    {"wq", kdb_cmdf_wq,  kdb_usgf_wq, 1, KDBX_REPEAT_NONE},

    /* block device, file system, char device, ... */
    {"bio", kdb_cmdf_bio,  kdb_usgf_bio, 1, KDBX_REPEAT_NONE},
    {"req", kdb_cmdf_req,  kdb_usgf_req, 1, KDBX_REPEAT_NONE},
    {"reqq", kdb_cmdf_reqq,  kdb_usgf_reqq, 1, KDBX_REPEAT_NONE},
    {"disks", kdb_cmdf_disks,  kdb_usgf_disks, 1, KDBX_REPEAT_NONE},
    {"blkdevs", kdb_cmdf_blkdevs,  kdb_usgf_blkdevs, 1, KDBX_REPEAT_NONE},

    /* network related */
    {"netdevs", kdb_cmdf_netdevs,  kdb_usgf_netdevs, 1, KDBX_REPEAT_NONE},
    {"netdev", kdb_cmdf_netdev,  kdb_usgf_netdev, 1, KDBX_REPEAT_NONE},
    {"socket", kdb_cmdf_socket, kdb_usgf_socket, 1, KDBX_REPEAT_NONE},
    {"skb", kdb_cmdf_skb, kdb_usgf_skb, 1, KDBX_REPEAT_NONE},

    {"sym",  kdb_cmdf_sym,   kdb_usgf_sym,   1, KDBX_REPEAT_NONE},
    {"mod",  kdb_cmdf_mods,  kdb_usgf_mods,  1, KDBX_REPEAT_NONE},

    /* KVM related */
    {"skvm", kdb_cmdf_skvm,  kdb_usgf_skvm, 1, KDBX_REPEAT_NONE},
    {"vms", kdb_cmdf_vms,  kdb_usgf_vms, 1, KDBX_REPEAT_NONE},
    {"vcpu", kdb_cmdf_vcpu,  kdb_usgf_vcpu,  1, KDBX_REPEAT_NONE},
    {"varch", kdb_cmdf_varch,  kdb_usgf_varch,  1, KDBX_REPEAT_NONE},
    {"dvmc", kdb_cmdf_dvmc,  kdb_usgf_dvmc, 1, KDBX_REPEAT_NONE},
    {"p2m", kdb_cmdf_p2m,  kdb_usgf_p2m, 1, KDBX_REPEAT_NONE},
    {"wept", kdb_cmdf_wept,  kdb_usgf_wept, 1, KDBX_REPEAT_NONE},
    {"wpt", kdb_cmdf_wpt,  kdb_usgf_wpt, 1, KDBX_REPEAT_NONE},
    {"kvmiodevs", kdb_cmdf_kvmiodevs,  kdb_usgf_kvmiodevs, 1, KDBX_REPEAT_NONE},
    {"virtq", kdb_cmdf_virtq,  kdb_usgf_virtq, 1, KDBX_REPEAT_NONE},
    {"vdevvq", kdb_cmdf_vdevvq,  kdb_usgf_vdevvq, 1, KDBX_REPEAT_NONE},
    {"virtscsi", kdb_cmdf_virtscsi,  kdb_usgf_virtscsi, 1, KDBX_REPEAT_NONE},
    {"viodev", kdb_cmdf_viodev,  kdb_usgf_viodev, 1, KDBX_REPEAT_NONE},
    {"viodrvr", kdb_cmdf_viodrvr,  kdb_usgf_viodrvr, 1, KDBX_REPEAT_NONE},
    {"viopcidev", kdb_cmdf_viopcidev,  kdb_usgf_viopcidev, 1, KDBX_REPEAT_NONE},
    {"vbusdrvrs", kdb_cmdf_vbusdrvrs,  kdb_usgf_vbusdrvrs, 1, KDBX_REPEAT_NONE},
    {"vbusdevs", kdb_cmdf_vbusdevs,  kdb_usgf_vbusdevs, 1, KDBX_REPEAT_NONE},
    {"vhostdevs", kdb_cmdf_vhostdevs,  kdb_usgf_vhostdevs, 1, KDBX_REPEAT_NONE},

#ifdef __KDBX_SUPPORT_FOR_HYPERV
    /* Hyper-V related */
    {"netvsc", kdb_cmdf_netvsc,  kdb_usgf_netvsc, 1, KDBX_REPEAT_NONE},
    {"vmbusc", kdb_cmdf_vmbusc,  kdb_usgf_vmbusc, 1, KDBX_REPEAT_NONE},
#endif

    /* tracing: avail in crashed state if kdbx itself traced */
    {"trcon", kdb_cmdf_trcon,  kdb_usgf_trcon,  1, KDBX_REPEAT_NONE},
    {"trcoff",kdb_cmdf_trcoff, kdb_usgf_trcoff, 1, KDBX_REPEAT_NONE},
    {"trcz",  kdb_cmdf_trcz,   kdb_usgf_trcz,   0, KDBX_REPEAT_NONE},
    {"trcp",  kdb_cmdf_trcp,   kdb_usgf_trcp,   1, KDBX_REPEAT_NONE},
    {"dtrcp",  kdb_cmdf_dtrcp,   kdb_usgf_dtrcp,   1, KDBX_REPEAT_NONE},

    {"bl", kdb_cmdf_bl, kdb_usgf_bl, 1, KDBX_REPEAT_NONE},
    {"cons", kdb_cmdf_cons, kdb_usgf_cons, 1, KDBX_REPEAT_NONE},
    {"uart", kdb_cmdf_uart, kdb_usgf_uart, 1, KDBX_REPEAT_NONE},
    {"usr1",  kdb_cmdf_usr1,   kdb_usgf_usr1,   1, KDBX_REPEAT_NONE},
    {"kdbcur",  kdb_cmdf_kdbcur,   kdb_usgf_kdbcur,   1, KDBX_REPEAT_NONE},
    {"kdbf",  kdb_cmdf_kdbf,   kdb_usgf_kdbf,   1, KDBX_REPEAT_NONE},
    {"kdbdbg",kdb_cmdf_kdbdbg, kdb_usgf_kdbdbg, 1, KDBX_REPEAT_NONE},
    {"reboot",kdb_cmdf_reboot, kdb_usgf_reboot, 1, KDBX_REPEAT_NONE},
    {"h",     kdb_cmdf_h,      kdb_usgf_h,      1, KDBX_REPEAT_NONE},

    {"", NULL, NULL, 0, 0},
  };
    kdb_cmd_tbl = _kdb_cmd_table;
    return;
}
