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

#if defined(__x86_64__)
    #define KDBF64 "%lx"
    #define KDBFL "%016lx"         /* print long all digits */
#else
    #define KDBF64 "%llx"
    #define KDBFL "%08lx"
#endif

#if XEN_VERSION >= 3 || XEN_SUBVERSION > 4       /* xen 3.5.x or above */
    #define KDB_LKDEF(l) ((l).raw.lock)
    #define KDB_PGLLE(t) ((t).tail)    /* page list last element ^%$#@ */
#else
    #define KDB_LKDEF(l) ((l).lock)
    #define KDB_PGLLE(t) ((t).prev)    /* page list last element ^%$#@ */
#endif

#define KDB_CMD_HISTORY_COUNT   32
#define CMD_BUFLEN              200     /* kdb_printf: max printline == 256 */

#define KDBMAXSBP 16                    /* max number of software breakpoints */
#define KDB_MAXARGC 16                  /* max args in a kdb command */
#define KDB_MAXBTP  8                   /* max display args in btp */

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
    domid_t  bp_domid;             /* which domain the bp belongs to */
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
       { "rax", offsetof(struct cpu_user_regs, rax) },
       { "rbx", offsetof(struct cpu_user_regs, rbx) },
       { "rcx", offsetof(struct cpu_user_regs, rcx) },
       { "rdx", offsetof(struct cpu_user_regs, rdx) },
       { "rsi", offsetof(struct cpu_user_regs, rsi) },
       { "rdi", offsetof(struct cpu_user_regs, rdi) },
       { "rbp", offsetof(struct cpu_user_regs, rbp) },
       { "rsp", offsetof(struct cpu_user_regs, rsp) },
       { "r8",  offsetof(struct cpu_user_regs, r8) },
       { "r9",  offsetof(struct cpu_user_regs, r9) },
       { "r10", offsetof(struct cpu_user_regs, r10) },
       { "r11", offsetof(struct cpu_user_regs, r11) },
       { "r12", offsetof(struct cpu_user_regs, r12) },
       { "r13", offsetof(struct cpu_user_regs, r13) },
       { "r14", offsetof(struct cpu_user_regs, r14) },
       { "r15", offsetof(struct cpu_user_regs, r15) },
       { "rflags", offsetof(struct cpu_user_regs, rflags) } };

static const int KDBBPSZ=1;                   /* size of KDB_BPINST is 1 byte*/
static kdbbyt_t kdb_bpinst = 0xcc;            /* breakpoint instr: INT3 */
static struct kdb_sbrkpt kdb_sbpa[KDBMAXSBP]; /* soft brkpt array/table */
static kdbtab_t *tbp;

static int kdb_set_bp(domid_t, kdbva_t, int, ulong *, char*, char*, char*);
static void kdb_print_uregs(struct cpu_user_regs *);


/* ===================== cmdline functions  ================================ */

/* lp points to a string of only alpha numeric chars terminated by '\n'.
 * Parse the string into argv pointers, and RETURN argc
 * Eg:  if lp --> "dr  sp\n" :  argv[0]=="dr\0"  argv[1]=="sp\0"  argc==2
 */
static int
kdb_parse_cmdline(char *lp, const char **argv)
{
    int i=0;

    for (; *lp == ' '; lp++);      /* note: isspace() skips '\n' also */
    while ( *lp != '\n' ) {
        if (i == KDB_MAXARGC) {
            kdbp("kdb: max args exceeded\n");
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

void
kdb_clear_prev_cmd()             /* so previous command is not repeated */
{
    tbp = NULL;
}

void
kdb_do_cmds(struct cpu_user_regs *regs)
{
    char *cmdlinep;
    const char *argv[KDB_MAXARGC];
    int argc = 0, curcpu = smp_processor_id();
    kdb_cpu_cmd_t result = KDB_CPU_MAIN_KDB;

    snprintf(kdb_prompt, sizeof(kdb_prompt), "[%d]xkdb> ", curcpu);

    while (result == KDB_CPU_MAIN_KDB) {
        cmdlinep = kdb_get_cmdline(kdb_prompt);
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
        if (kdb_sys_crash && tbp->kdb_cmd_func && !tbp->kdb_cmd_crash_avail) {
            kdbp("cmd not available in fatal/crashed state....\n");
            continue;
        }
        if (tbp->kdb_cmd_func) {
            result = (*tbp->kdb_cmd_func)(argc, argv, regs);
            if (tbp->kdb_cmd_repeat == KDB_REPEAT_NONE)
                tbp = NULL;
        } else
            kdbp("kdb: Unknown cmd: %s\n", cmdlinep);
    }
    kdb_cpu_cmd[curcpu] = result;
    return;
}

/* ===================== Util functions  ==================================== */

int
kdb_vcpu_valid(struct vcpu *in_vp)
{
    struct domain *dp;
    struct vcpu *vp;

    for(dp=domain_list; in_vp && dp; dp=dp->next_in_list)
        for_each_vcpu(dp, vp)
            if (in_vp == vp)
                return 1;
    return 0;     /* not found */
}

/*
 * Given a symbol, find it's address
 */
static kdbva_t
kdb_sym2addr(const char *p, domid_t domid)
{
    kdbva_t addr;

    KDBGP1("sym2addr: p:%s domid:%d\n", p, domid);
    if (domid == DOMID_IDLE)
        addr = address_lookup((char *)p);
    else
        addr = (kdbva_t)kdb_guest_sym2addr((char *)p, domid);
    KDBGP1("sym2addr: exit: addr returned:0x%lx\n", addr);
    return addr;
}

/*
 * convert ascii to int decimal (base 10). 
 * Return: 0 : failed to convert, otherwise 1 
 */
static int
kdb_str2deci(const char *strp, int *intp)
{
    const char *endp;

    KDBGP2("str2deci: str:%s\n", strp);
    if (!isdigit(*strp))
        return 0;
    *intp = (int)simple_strtoul(strp, &endp, 10);
    if (endp != strp+strlen(strp))
        return 0;
    KDBGP2("str2deci: intval:$%d\n", *intp);
    return 1;
}
/*
 * convert ascii to long. NOTE: base is 16
 * Return: 0 : failed to convert, otherwise 1 
 */
static int
kdb_str2ulong(const char *strp, ulong *longp)
{
    ulong val;
    const char *endp;

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
static int
kdb_str2addr(const char *strp, kdbva_t *addrp, domid_t id)
{
    kdbva_t addr;
    const char *endp;

    /* assume it's an address */
    KDBGP2("str2addr: str:%s id:%d\n", strp, id);
    addr = (kdbva_t)simple_strtoul(strp, &endp, 16); /*handles leading 0x */
    if (endp != strp+strlen(strp))
        if ( !(addr=kdb_sym2addr(strp, id)) )
            return 0;
    *addrp = addr;
    KDBGP2("str2addr: addr:0x%lx\n", addr);
    return 1;
}

/* Given domid, return ptr to struct domain 
 * IF domid == DOMID_IDLE return ptr to idle_domain 
 * IF domid == valid domain, return ptr to domain struct
 * else domid is bad and return NULL
 */
static struct domain *
kdb_domid2ptr(domid_t domid)
{
    struct domain *dp;

    /* get_domain_by_id() ret NULL for both DOMID_IDLE and bad domids */
    if (domid == DOMID_IDLE)
        dp = idle_vcpu[smp_processor_id()]->domain;
    else 
        dp = get_domain_by_id(domid);   /* NULL now means bad domid */
    return dp;
}

/*
 * Returns:  0: failed. invalid domid or string, *idp not changed.
 */
static int
kdb_str2domid(const char *domstr, domid_t *idp, int perr)
{
    int id;
    if (!kdb_str2deci(domstr, &id) || !kdb_domid2ptr((domid_t)id)) {
        if (perr)
            kdbp("Invalid domid:%s\n", domstr);
        return 0;
    }
    *idp = (domid_t)id;
    return 1;
}

static struct domain *
kdb_strdomid2ptr(const char *domstr, int perror)
{
    domid_t domid;
    if (kdb_str2domid(domstr, &domid, perror)) {
        return(kdb_domid2ptr(domid));
    }
    return NULL;
}

/* return a guest bitness: 32 or 64 */
int
kdb_guest_bitness(domid_t domid)
{
    const int HYPSZ = sizeof(long) * 8;
    struct domain *dp = kdb_domid2ptr(domid);
    int retval; 

    if (is_idle_domain(dp))
        retval = HYPSZ;
    else if (!is_pv_domain(dp))
        retval = (hvm_long_mode_enabled(dp->vcpu[0])) ? HYPSZ : 32;
    else 
        retval = is_pv_32bit_domain(dp) ? 32 : HYPSZ;
    KDBGP1("gbitness: domid:%d dp:%p bitness:%d\n", domid, dp, retval);
    return retval;
}

/* kdb_print_spin_lock(&xyz_lock, "xyz_lock:", "\n"); */
static void
kdb_print_spin_lock(char *strp, spinlock_t *lkp, char *nlp)
{
#if XEN_VERSION > 3 && XEN_SUBVERSION > 3       /* xen 4.4.x or above */
    kdbp("%s %x %d %d%s", strp, lkp->tickets.head_tail, lkp->recurse_cpu,
         lkp->recurse_cnt, nlp);
#else
    kdbp("%s %04hx %d %d%s", strp, KDB_LKDEF(*lkp), lkp->recurse_cpu,
         lkp->recurse_cnt, nlp);
#endif
}

/* check if register string is valid. if yes, return offset to the register
 * in cpu_user_regs, else return -1 */
static int
kdb_valid_reg(const char *nmp) 
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

/* ===================== util struct funcs ================================= */
static void
kdb_prnt_timer(struct timer *tp)
{
#if XEN_SUBVERSION == 0 
    kdbp(" expires:%016lx expires_end:%016lx cpu:%d status:%x\n", tp->expires, 
         tp->expires_end, tp->cpu, tp->status);
#else
    kdbp(" expires:%016lx cpu:%d status:%x\n", tp->expires, tp->cpu,tp->status);
#endif
    kdbp(" function data:%p ptr:%p ", tp->data, tp->function);
    kdb_prnt_addr2sym(DOMID_IDLE, (kdbva_t)tp->function, "\n");
}

static void 
kdb_prnt_periodic_time(struct periodic_time *ptp)
{
    kdbp(" next:%p prev:%p\n", ptp->list.next, ptp->list.prev);
    kdbp(" on_list:%d one_shot:%d dont_freeze:%d irq_issued:%d src:%x irq:%x\n",
         ptp->on_list, ptp->one_shot, ptp->do_not_freeze, ptp->irq_issued,
         ptp->source, ptp->irq);
    kdbp(" vcpu:%p pending_intr_nr:%08x period:%016lx\n", ptp->vcpu,
         ptp->pending_intr_nr, ptp->period);
    kdbp(" scheduled:%016lx last_plt_gtime:%016lx\n", ptp->scheduled,
         ptp->last_plt_gtime);
    kdbp(" \n          timer info:\n");
    kdb_prnt_timer(&ptp->timer);
    kdbp("\n");
}

/* ===================== cmd functions  ==================================== */

/*
 * FUNCTION: Disassemble instructions
 */
static kdb_cpu_cmd_t
kdb_usgf_dis(void)
{
    kdbp("dis [addr|sym][num][domid] : Disassemble instrs\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_dis(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int num = 8;                           /* display 8 instr by default */
    static kdbva_t addr = BFD_INVAL;
    static domid_t domid;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dis();

    if (argc != -1)      /* not a command repeat */
    {
        /* user gave addr but not domid, the addr then is xen */
        if (argc > 1 && argc < 4)
            domid = DOMID_IDLE;
        else
            domid = guest_mode(regs) ?  current->domain->domain_id : DOMID_IDLE;
    }

    if (argc >= 4 && !kdb_str2domid(argv[3], &domid, 1)) { 
        return KDB_CPU_MAIN_KDB;
    } 
    if (argc >= 3 && !kdb_str2deci(argv[2], &num)) {
        kdbp("kdb:Invalid num\n");
        return KDB_CPU_MAIN_KDB;
    } 
    if (argc > 1 && !kdb_str2addr(argv[1], &addr, domid)) {
        kdbp("kdb:Invalid addr/sym\n");
        kdbp("(num has to be specified if providing domid)\n");
        return KDB_CPU_MAIN_KDB;
    } 
    if (argc == 1)                    /* not command repeat */
        addr = regs->KDBIP;           /* PC is the default */
    else if (addr == BFD_INVAL) {
        kdbp("kdb:Invalid addr/sym\n");
        return KDB_CPU_MAIN_KDB;
    }
    addr = kdb_print_instr(addr, num, domid);
    return KDB_CPU_MAIN_KDB;
}

/* FUNCTION: kdb_cmdf_dism() Toggle disassembly syntax from Intel to ATT/GAS */
static kdb_cpu_cmd_t
kdb_usgf_dism(void)
{
    kdbp("dism: toggle disassembly mode between ATT/GAS and INTEL\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_dism(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dism();

    kdb_toggle_dis_syntax();
    return KDB_CPU_MAIN_KDB;
}

static void
_kdb_show_guest_stack(domid_t domid, kdbva_t ipaddr, kdbva_t spaddr)
{
    kdbva_t val;
    int num=0, max=0, rd = kdb_guest_bitness(domid)/8;

    kdb_print_instr(ipaddr, 1, domid);
    KDBGP("_guest_stack:sp:%lx domid:%d rd:$%d\n", spaddr, domid, rd);
    val = 0;                          /* must zero, in case guest is 32bit */
    while((kdb_read_mem(spaddr,(kdbbyt_t *)&val,rd,domid)==rd) && num < 16){
        KDBGP1("gstk:addr:%lx val:%lx\n", spaddr, val);
        if (kdb_is_addr_guest_text(val, domid)) {
            kdb_print_instr(val, 1, domid);
            num++;
        }
        if (max++ > 10000)            /* don't walk down the stack forever */
            break;                    /* 10k is chosen randomly */
        spaddr += rd;
    }
}

/* Read guest memory and display address that looks like text. */
static void
kdb_show_guest_stack(struct cpu_user_regs *regs, struct vcpu *vcpup)
{
    kdbva_t ipaddr=regs->KDBIP, spaddr = regs->KDBSP;
    domid_t domid = vcpup->domain->domain_id;

    ASSERT(domid != DOMID_IDLE);
    _kdb_show_guest_stack(domid, ipaddr, spaddr);
}

/* display stack. if vcpu ptr given, then display stack for that. Otherwise,
 * use current regs */
static kdb_cpu_cmd_t
kdb_usgf_f(void)
{
    kdbp("f [vcpu-ptr]: dump current/vcpu stack\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_f(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_f();

    if (argc > 1 ) {
        struct vcpu *vp;
        if (!kdb_str2ulong(argv[1], (ulong *)&vp) || !kdb_vcpu_valid(vp)) {
            kdbp("kdb: Bad VCPU ptr:%s\n", argv[1]);
            return KDB_CPU_MAIN_KDB;
        }
        kdb_show_guest_stack(&vp->arch.user_regs, vp);
        return KDB_CPU_MAIN_KDB;
    }
    if (guest_mode(regs))
        kdb_show_guest_stack(regs, current);
    else
        show_trace(regs);
    return KDB_CPU_MAIN_KDB;
}

/* given an spaddr and domid for guest, dump stack */
static kdb_cpu_cmd_t
kdb_usgf_fg(void)
{
    kdbp("fg domid RIP ESP: dump guest stack given domid, RIP, and ESP\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_fg(int argc, const char **argv, struct cpu_user_regs *regs)
{
    domid_t domid;
    kdbva_t ipaddr, spaddr;

    if (argc != 4) 
        return kdb_usgf_fg();

    if (kdb_str2domid(argv[1], &domid, 1)==0) {
        return KDB_CPU_MAIN_KDB;
    }
    if (kdb_str2ulong(argv[2], &ipaddr)==0) {
        kdbp("Bad ipaddr:%s\n", argv[2]);
        return KDB_CPU_MAIN_KDB;
    }
    if (kdb_str2ulong(argv[3], &spaddr)==0) {
        kdbp("Bad spaddr:%s\n", argv[3]);
        return KDB_CPU_MAIN_KDB;
    }
    _kdb_show_guest_stack(domid, ipaddr, spaddr);
    return KDB_CPU_MAIN_KDB;
}

/* Display kdb stack. for debugging kdb itself */
static kdb_cpu_cmd_t
kdb_usgf_kdbf(void)
{
    kdbp("kdbf: display kdb stack. for debugging kdb only\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_kdbf(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_kdbf();

    kdb_trap_immed(KDB_TRAP_KDBSTACK);
    return KDB_CPU_MAIN_KDB;
}

/* worker function to display memory. Request could be for any guest, domid.
 * Also address could be machine or virtual */
static void
_kdb_display_mem(kdbva_t *addrp, int *lenp, int wordsz, int domid, int is_maddr)
{
    #define DDBUFSZ 4096

    kdbbyt_t buf[DDBUFSZ], *bp;
    int numrd, bytes;
    int len = *lenp;
    kdbva_t addr = *addrp;

    /* round len down to wordsz boundry because on intel endian, printing
     * characters is not prudent, (long and ints can't be interpreted 
     * easily) */
    len &= ~(wordsz-1);
    len = KDBMIN(DDBUFSZ, len);
    len = len ? len : wordsz;

    KDBGP("dmem:addr:%lx buf:%p len:$%d domid:%d sz:$%d maddr:%d\n", addr,
          buf, len, domid, wordsz, is_maddr);
    if (is_maddr)
        numrd=kdb_read_mmem((kdbma_t)addr, buf, len);
    else
        numrd=kdb_read_mem(addr, buf, len, domid);
    if (numrd != len)
        kdbp("Memory read error. Bytes read:$%d\n", numrd);

    for (bp = buf; numrd > 0;) {
        kdbp("%016lx: ", addr); 

        /* display 16 bytes per line */
        for (bytes=0; bytes < 16 && numrd > 0; bytes += wordsz) {
            if (numrd >= wordsz) {
                if (wordsz == 8)
                    kdbp(" %016lx", *(long *)bp);
                else
                    kdbp(" %08x", *(int *)bp);
                bp += wordsz;
                numrd -= wordsz;
                addr += wordsz;
            }
        }
        kdbp("\n");
        continue;
    }
    *lenp = len;
    *addrp = addr;
}

/* display machine mem, ie, the given address is machine address */
static kdb_cpu_cmd_t 
kdb_display_mmem(int argc, const char **argv, int wordsz, kdb_usgf_t usg_fp)
{
    static kdbma_t maddr;
    static int len;
    static domid_t id = DOMID_IDLE;

    if (argc == -1) {
        _kdb_display_mem(&maddr, &len, wordsz, id, 1);  /* cmd repeat */
        return KDB_CPU_MAIN_KDB;
    }
    if (argc <= 1 || *argv[1] == '?')
        return (*usg_fp)();

    /* check if num of bytes to display is given by user */
    if (argc >= 3) {
        if (!kdb_str2deci(argv[2], &len)) {
            kdbp("Invalid length:%s\n", argv[2]);
            return KDB_CPU_MAIN_KDB;
        } 
    } else
        len = 32;                                     /* default read len */

    if (!kdb_str2ulong(argv[1], &maddr)) {
        kdbp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    _kdb_display_mem(&maddr, &len, wordsz, 0, 1);
    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Dispaly machine Memory Word
 */
static kdb_cpu_cmd_t
kdb_usgf_dwm(void)
{
    kdbp("dwm:  maddr|sym [num] : dump memory word given machine addr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_dwm(int argc, const char **argv, struct cpu_user_regs *regs)
{
    return kdb_display_mmem(argc, argv, 4, kdb_usgf_dwm);
}

/* 
 * FUNCTION: Dispaly machine Memory DoubleWord 
 */
static kdb_cpu_cmd_t
kdb_usgf_ddm(void)
{
    kdbp("ddm:  maddr|sym [num] : dump double word given machine addr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_ddm(int argc, const char **argv, struct cpu_user_regs *regs)
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
static kdb_cpu_cmd_t 
kdb_display_mem(int argc, const char **argv, int wordsz, kdb_usgf_t usg_fp)
{
    static kdbva_t addr;
    static int len;
    static domid_t id = DOMID_IDLE;

    if (argc == -1) {
        _kdb_display_mem(&addr, &len, wordsz, id, 0);  /* cmd repeat */
        return KDB_CPU_MAIN_KDB;
    }
    if (argc <= 1 || *argv[1] == '?')
        return (*usg_fp)();

    id = DOMID_IDLE;                /* not a command repeat, reset dom id */
    if (argc >= 4) { 
        if (!kdb_str2domid(argv[3], &id, 1)) 
            return KDB_CPU_MAIN_KDB;
    }
    /* check if num of bytes to display is given by user */
    if (argc >= 3) {
        if (!kdb_str2deci(argv[2], &len)) {
            kdbp("Invalid length:%s\n", argv[2]);
            return KDB_CPU_MAIN_KDB;
        } 
    } else
        len = 32;                       /* default read len */
    if (!kdb_str2addr(argv[1], &addr, id)) {
        kdbp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }

    _kdb_display_mem(&addr, &len, wordsz, id, 0);
    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Dispaly Memory Word
 */
static kdb_cpu_cmd_t
kdb_usgf_dw(void)
{
    kdbp("dw vaddr|sym [num][domid] : dump mem word. num required for domid\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_dw(int argc, const char **argv, struct cpu_user_regs *regs)
{
    return kdb_display_mem(argc, argv, 4, kdb_usgf_dw);
}

/* 
 * FUNCTION: Dispaly Memory DoubleWord 
 */
static kdb_cpu_cmd_t
kdb_usgf_dd(void)
{
    kdbp("dd vaddr|sym [num][domid] : dump dword. num required for domid\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_dd(int argc, const char **argv, struct cpu_user_regs *regs)
{
    return kdb_display_mem(argc, argv, 8, kdb_usgf_dd);
}

/* 
 * FUNCTION: Modify Memory Word 
 */
static kdb_cpu_cmd_t
kdb_usgf_mw(void)
{
    kdbp("mw vaddr|sym val [domid] : modify memory word in vaddr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_mw(int argc, const char **argv, struct cpu_user_regs *regs)
{
    ulong val;
    kdbva_t addr;
    domid_t id = DOMID_IDLE;

    if (argc < 3) {
        return kdb_usgf_mw();
    }
    if (argc >=4) {
        if (!kdb_str2domid(argv[3], &id, 1)) 
            return KDB_CPU_MAIN_KDB;
    }
    if (!kdb_str2ulong(argv[2], &val)) {
        kdbp("Invalid val: %s\n", argv[2]);
        return KDB_CPU_MAIN_KDB;
    }
    if (!kdb_str2addr(argv[1], &addr, id)) {
        kdbp("Invalid addr/sym: %s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    if (kdb_write_mem(addr, (kdbbyt_t *)&val, 4, id) != 4)
        kdbp("Unable to set 0x%lx to 0x%lx\n", addr, val);
    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Modify Memory DoubleWord 
 */
static kdb_cpu_cmd_t
kdb_usgf_md(void)
{
    kdbp("md vaddr|sym val [domid] : modify memory dword in vaddr\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_md(int argc, const char **argv, struct cpu_user_regs *regs)
{
    ulong val;
    kdbva_t addr;
    domid_t id = DOMID_IDLE;

    if (argc < 3) {
        return kdb_usgf_md();
    }
    if (argc >=4) {
        if (!kdb_str2domid(argv[3], &id, 1)) {
            return KDB_CPU_MAIN_KDB;
        }
    }
    if (!kdb_str2ulong(argv[2], &val)) {
        kdbp("Invalid val: %s\n", argv[2]);
        return KDB_CPU_MAIN_KDB;
    }
    if (!kdb_str2addr(argv[1], &addr, id)) {
        kdbp("Invalid addr/sym: %s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    if (kdb_write_mem(addr, (kdbbyt_t *)&val,sizeof(val),id) != sizeof(val))
        kdbp("Unable to set 0x%lx to 0x%lx\n", addr, val);

    return KDB_CPU_MAIN_KDB;
}

struct  Xgt_desc_struct {
    unsigned short size;
    unsigned long address __attribute__((packed));
};

void
kdb_show_special_regs(struct cpu_user_regs *regs)
{
    struct Xgt_desc_struct desc;
    unsigned short tr;                 /* Task Register segment selector */
    __u64 efer;

    kdbp("\nSpecial Registers:\n");
    __asm__ __volatile__ ("sidt  (%0) \n" :: "a"(&desc) : "memory");
    kdbp("IDTR: addr: %016lx limit: %04x\n", desc.address, desc.size);
    __asm__ __volatile__ ("sgdt  (%0) \n" :: "a"(&desc) : "memory");
    kdbp("GDTR: addr: %016lx limit: %04x\n", desc.address, desc.size);

    kdbp("cr0: %016lx  cr2: %016lx\n", read_cr0(), read_cr2());
    kdbp("cr3: %016lx  cr4: %016lx\n", read_cr3(), read_cr4());
    __asm__ __volatile__ ("str (%0) \n":: "a"(&tr) : "memory");
    kdbp("TR: %x\n", tr);

    rdmsrl(MSR_EFER, efer);    /* IA32_EFER */
    kdbp("efer:"KDBF64" LMA(IA-32e mode):%d SCE(syscall/sysret):%d\n",
         efer, ((efer&EFER_LMA) != 0), ((efer&EFER_SCE) != 0));

    kdbp("DR0: %016lx  DR1:%016lx  DR2:%016lx\n", kdb_rd_dbgreg(0),
         kdb_rd_dbgreg(1), kdb_rd_dbgreg(2)); 
    kdbp("DR3: %016lx  DR6:%016lx  DR7:%016lx\n", kdb_rd_dbgreg(3),
         kdb_rd_dbgreg(6), kdb_rd_dbgreg(7)); 
}

/* 
 * FUNCTION: Dispaly Registers. If "sp" argument, then display additional regs
 */
static kdb_cpu_cmd_t
kdb_usgf_dr(void)
{
    kdbp("dr [sp]: display registers. sp to display special regs also\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_dr(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dr();

    KDBGP1("regs:%p .rsp:%lx .rip:%lx\n", regs, regs->rsp, regs->rip);
    show_registers(regs);
    if (argc > 1 && !strcmp(argv[1], "sp")) 
        kdb_show_special_regs(regs);
    return KDB_CPU_MAIN_KDB;
}

/* show registers on stack bottom where guest context is. same as dr if
 * not running in guest mode */
static kdb_cpu_cmd_t
kdb_usgf_drg(void)
{
    kdbp("drg: display active guest registers at stack bottom\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_drg(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_drg();

    kdbp("\tNote: ds/es/fs/gs etc.. are not saved from the cpu\n");
    kdb_print_uregs(guest_cpu_user_regs());
    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Modify Register
 */
static kdb_cpu_cmd_t
kdb_usgf_mr(void)
{
    kdbp("mr reg val : Modify Register. val assumed in hex\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_mr(int argc, const char **argv, struct cpu_user_regs *regs)
{
    const char *argp;
    int regoffs;
    ulong val;

    if (argc != 3 || !kdb_str2ulong(argv[2], &val)) {
        return kdb_usgf_mr();
    }
    argp = argv[1];

#if defined(__x86_64__)
    if ((regoffs=kdb_valid_reg(argp)) != -1)
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
        kdbp("Error. Bad register : %s\n", argp);

    return KDB_CPU_MAIN_KDB;
}

/* 
 * FUNCTION: Single Step
 */
static kdb_cpu_cmd_t
kdb_usgf_ss(void)
{
    kdbp("ss: single step\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_ss(int argc, const char **argv, struct cpu_user_regs *regs)
{
    #define KDB_HALT_INSTR 0xf4

    kdbbyt_t byte;
    struct domain *dp = current->domain;
    domid_t id = guest_mode(regs) ? dp->domain_id : DOMID_IDLE;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_ss();

    KDBGP("enter kdb_cmdf_ss \n");
    if (!regs) {
        kdbp("%s: regs not available\n", __FUNCTION__);
        return KDB_CPU_MAIN_KDB;
    }
    if (kdb_read_mem(regs->KDBIP, &byte, 1, id) == 1) {
        if (byte == KDB_HALT_INSTR) {
            kdbp("kdb: jumping over halt instruction\n");
            regs->KDBIP++;
        }
    } else {
        kdbp("kdb: Failed to read byte at: %lx\n", regs->KDBIP);
        return KDB_CPU_MAIN_KDB;
    }
    if (guest_mode(regs) && !is_pv_vcpu(current)) {
        dp->debugger_attached = 1;  /* see svm_do_resume/vmx_do_ */

        /* will set MTF in vmx_intr_assist */
        current->arch.hvm_vcpu.single_step = 1;
    } else
        regs->eflags |= X86_EFLAGS_TF;

    return KDB_CPU_SS;
}

/* 
 * FUNCTION: Next Instruction, step over the call instr to the next instr
 */
static kdb_cpu_cmd_t
kdb_usgf_ni(void)
{
    kdbp("ni: single step, stepping over function calls\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_ni(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int sz, i;
    domid_t id=guest_mode(regs) ? current->domain->domain_id:DOMID_IDLE;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_ni();

    KDBGP("enter kdb_cmdf_ni \n");
    if (!regs) {
        kdbp("%s: regs not available\n", __FUNCTION__);
        return KDB_CPU_MAIN_KDB;
    }
    if ((sz=kdb_check_call_instr(id, regs->KDBIP)) == 0)  /* !call instr */
        return kdb_cmdf_ss(argc, argv, regs);         /* just do ss */

    if ((i=kdb_set_bp(id, regs->KDBIP+sz, 1,0,0,0,0)) >= KDBMAXSBP) /* failed */
        return KDB_CPU_MAIN_KDB;

    kdb_sbpa[i].bp_ni = 1;
    if (guest_mode(regs) && !is_pv_vcpu(current))
        current->arch.hvm_vcpu.single_step = 0;
    else
        regs->eflags &= ~X86_EFLAGS_TF;

    return KDB_CPU_NI;
}

static void
kdb_btf_enable(void)
{
    u64 debugctl;
    rdmsrl(MSR_IA32_DEBUGCTLMSR, debugctl);
    wrmsrl(MSR_IA32_DEBUGCTLMSR, debugctl | 0x2);
}

/* 
 * FUNCTION: Single Step to branch. Doesn't seem to work very well.
 */
static kdb_cpu_cmd_t
kdb_usgf_ssb(void)
{
    kdbp("ssb: singe step to branch\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_ssb(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_ssb();

    KDBGP("kdb: enter kdb_cmdf_ssb\n");
    if (!regs) {
        kdbp("%s: regs not available\n", __FUNCTION__);
        return KDB_CPU_MAIN_KDB;
    }
    if (!is_pv_vcpu(current)) 
        current->domain->debugger_attached = 1;        /* vmx/svm_do_resume()*/

    regs->eflags |= X86_EFLAGS_TF;
    kdb_btf_enable();
    return KDB_CPU_SS;
}

/* 
 * FUNCTION: Continue Execution. TF must be cleared here as this could run on 
 *           any cpu. Hence not OK to do it from kdb_end_session.
 */
static kdb_cpu_cmd_t
kdb_usgf_go(void)
{
    kdbp("go: leave kdb and continue execution\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_go(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_go();

    regs->eflags &= ~X86_EFLAGS_TF;
    return KDB_CPU_GO;
}

/* All cpus must display their current context */
static kdb_cpu_cmd_t 
kdb_cpu_status_all(int ccpu, struct cpu_user_regs *regs)
{
    int cpu;
    for_each_online_cpu(cpu) {
        if (cpu == ccpu) {
            kdbp("[%d]", ccpu);
            kdb_display_pc(regs);
        } else {
            if (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE)   /* hung cpu */
                continue;
            kdb_cpu_cmd[cpu] = KDB_CPU_SHOWPC;
            while (kdb_cpu_cmd[cpu]==KDB_CPU_SHOWPC);
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
static kdb_cpu_cmd_t
kdb_usgf_cpu(void)
{
    kdbp("cpu [all|num]: none will switch back to initial cpu\n");
    kdbp("               cpunum to switch to the vcpu. all to show status\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_cpu(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int cpu;
    int ccpu = smp_processor_id();

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_cpu();

    if (argc > 1) {
        if (!strcmp(argv[1], "all"))
            return kdb_cpu_status_all(ccpu, regs);

        cpu = (int)simple_strtoul(argv[1], NULL, 0); /* handles 0x */
        if (cpu >= 0 && cpu < NR_CPUS && cpu != ccpu && 
            cpu_online(cpu) && kdb_cpu_cmd[cpu] == KDB_CPU_PAUSE)
        {
                kdbp("Switching to cpu:%d\n", cpu);
                kdb_cpu_cmd[cpu] = KDB_CPU_MAIN_KDB;

                /* clear any single step on the current cpu */
                regs->eflags &= ~X86_EFLAGS_TF;
                return KDB_CPU_PAUSE;
        } else {
                if (cpu != ccpu)
                    kdbp("Unable to switch to cpu:%d\n", cpu);
                else {
                    kdb_display_pc(regs);
                }
                return KDB_CPU_MAIN_KDB;
        }
    }
    /* no arg means back to initial cpu */
    if (!kdb_sys_crash && ccpu != kdb_init_cpu) {
        if (kdb_cpu_cmd[kdb_init_cpu] == KDB_CPU_PAUSE) {
            regs->eflags &= ~X86_EFLAGS_TF;
            kdb_cpu_cmd[kdb_init_cpu] = KDB_CPU_MAIN_KDB;
            return KDB_CPU_PAUSE;
        } else
            kdbp("Unable to switch to: %d\n", kdb_init_cpu);
    }
    return KDB_CPU_MAIN_KDB;
}

/* send NMI to all or given CPU. Must be crashed/fatal state */
static kdb_cpu_cmd_t
kdb_usgf_nmi(void)
{
    kdbp("nmi cpu#|all: send nmi cpu/s. must reboot when done with kdb\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_nmi(int argc, const char **argv, struct cpu_user_regs *regs)
{
    cpumask_t cpumask;
    int ccpu = smp_processor_id();

    if (argc <= 1 || (argc > 1 && *argv[1] == '?'))
        return kdb_usgf_nmi();

    if (!kdb_sys_crash) {
        kdbp("kdb: nmi cmd available in crashed state only\n");
        return KDB_CPU_MAIN_KDB;
    }
    if (!strcmp(argv[1], "all"))
        cpumask = cpu_online_map;
    else {
        int cpu = (int)simple_strtoul(argv[1], NULL, 0);
        if (cpu >= 0 && cpu < NR_CPUS && cpu != ccpu && cpu_online(cpu))
            cpumask = *cpumask_of(cpu);
        else {
            kdbp("KDB nmi: invalid cpu %s\n", argv[1]);
            return KDB_CPU_MAIN_KDB;
        }
    }
    kdb_nmi_pause_cpus(cpumask);
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_percpu(void)
{
    kdbp("percpu: display per cpu pointers\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_percpu(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_percpu();
    kdb_dump_time_pcpu();
    return KDB_CPU_MAIN_KDB;
}

/* ========================= Breakpoints ==================================== */

static void
kdb_prnt_bp_cond(int bpnum)
{
    struct kdb_bpcond *bpcp = &kdb_sbpa[bpnum].u.bp_cond;

    if (bpcp->bp_cond_status == 1) {
        kdbp("     ( %s %c%c %lx )\n", 
             kdb_regoffs_to_name(bpcp->bp_cond_lhs),
             bpcp->bp_cond_type == 1 ? '=' : '!', '=', bpcp->bp_cond_rhs);
    } else {
        kdbp("     ( %lx %c%c %lx )\n", bpcp->bp_cond_lhs,
             bpcp->bp_cond_type == 1 ? '=' : '!', '=', bpcp->bp_cond_rhs);
    }
}

static void
kdb_prnt_bp_extra(int bpnum)
{
    if (kdb_sbpa[bpnum].bp_type == 2) {
        ulong i, arg, *btp = kdb_sbpa[bpnum].u.bp_btp;
        
        kdbp("   will trace ");
        for (i=0; i < KDB_MAXBTP && btp[i]; i++)
            if ((arg=btp[i]) < sizeof (struct cpu_user_regs)) {
                kdbp(" %s ", kdb_regoffs_to_name(arg));
            } else {
                kdbp(" %lx ", arg);
            }
        kdbp("\n");

    } else if (kdb_sbpa[bpnum].bp_type == 1)
        kdb_prnt_bp_cond(bpnum);
}

/*
 * List software breakpoints
 */
static kdb_cpu_cmd_t
kdb_display_sbkpts(void)
{
    int i;
    for(i=0; i < KDBMAXSBP; i++)
        if (kdb_sbpa[i].bp_addr && !kdb_sbpa[i].bp_deleted) {
            struct domain *dp = kdb_domid2ptr(kdb_sbpa[i].bp_domid);

            if (dp == NULL || dp->is_dying) {
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
                continue;
            }
            kdbp("[%d]: domid:%d 0x%lx   ", i, 
                 kdb_sbpa[i].bp_domid, kdb_sbpa[i].bp_addr);
            kdb_prnt_addr2sym(kdb_sbpa[i].bp_domid, kdb_sbpa[i].bp_addr,"\n");
            kdb_prnt_bp_extra(i);
        }
    return KDB_CPU_MAIN_KDB;
}

/*
 * Check if any breakpoints that we need to install (delayed install)
 * Returns: 1 if yes, 0 if none.
 */
int
kdb_swbp_exists(void)
{
    int i;
    for (i=0; i < KDBMAXSBP; i++)
        if (kdb_sbpa[i].bp_addr && !kdb_sbpa[i].bp_deleted)
            return 1;
    return 0;
}
/*
 * Check if any breakpoints were deleted this kdb session
 * Returns: 0 if none, 1 if yes
 */
static int
kdb_swbp_deleted(void)
{
    int i;
    for (i=0; i < KDBMAXSBP; i++)
        if (kdb_sbpa[i].bp_addr && kdb_sbpa[i].bp_deleted)
            return 1;
    return 0;
}

/*
 * Flush deleted sw breakpoints
 */
void
kdb_flush_swbp_table(void)
{
    int i;
    KDBGP("ccpu:%d flush_swbp_table: deleted:%x\n", smp_processor_id(), 
          kdb_swbp_deleted());
    for(i=0; i < KDBMAXSBP; i++)
        if (kdb_sbpa[i].bp_addr && kdb_sbpa[i].bp_deleted) {
            KDBGP("flush:[%x] addr:0x%lx\n",i,kdb_sbpa[i].bp_addr);
            memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
        }
}

/*
 * Delete/Clear a sw breakpoint
 */
static kdb_cpu_cmd_t
kdb_usgf_bc(void)
{
    kdbp("bc $num|all : clear given or all breakpoints\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_bc(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int i, bpnum = -1, delall = 0;
    const char *argp;

    if (argc != 2 || *argv[1] == '?')
        return kdb_usgf_bc();

    if (!kdb_swbp_exists()) {
        kdbp("No breakpoints are set\n");
        return KDB_CPU_MAIN_KDB;
    }
    argp = argv[1];

    if (!strcmp(argp, "all"))
        delall = 1;
    else if (!kdb_str2deci(argp, &bpnum) || bpnum < 0 || bpnum > KDBMAXSBP) {
        kdbp("Invalid bpnum: %s\n", argp);
        return KDB_CPU_MAIN_KDB;
    }
    for (i=0; i < KDBMAXSBP; i++) {
        if (delall && kdb_sbpa[i].bp_addr) {
            kdbp("Deleted breakpoint [%x] addr:0x%lx domid:%d\n", 
                 (int)i, kdb_sbpa[i].bp_addr, kdb_sbpa[i].bp_domid);
            if (kdb_sbpa[i].bp_just_added)
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
            else
                kdb_sbpa[i].bp_deleted = 1;
            continue;
        }
        if (bpnum != -1 && bpnum == i) {
            kdbp("Deleted breakpoint [%x] at 0x%lx domid:%d\n", 
                 (int)i, kdb_sbpa[i].bp_addr, kdb_sbpa[i].bp_domid);
            if (kdb_sbpa[i].bp_just_added)
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
            else
                kdb_sbpa[i].bp_deleted = 1;
            break;
        }
    }
    if (i >= KDBMAXSBP && !delall)
        kdbp("Unable to delete breakpoint: %s\n", argp);

    return KDB_CPU_MAIN_KDB;
}

/*
 * Install a breakpoint in the given array entry
 * Returns: 0 : failed to install
 *          1 : installed successfully
 */
static int
kdb_install_swbp(int idx)                   /* which entry in the bp array */
{
    kdbva_t addr = kdb_sbpa[idx].bp_addr;
    domid_t domid = kdb_sbpa[idx].bp_domid;
    kdbbyt_t *p = &kdb_sbpa[idx].bp_originst;
    struct domain *dp = kdb_domid2ptr(domid);

    if (dp == NULL || dp->is_dying) {
        memset(&kdb_sbpa[idx], 0, sizeof(kdb_sbpa[idx]));
        kdbp("Removed bp %d addr:%p domid:%d\n", idx, addr, domid);
        return 0;
    }

    if (kdb_read_mem(addr, p, KDBBPSZ, domid) != KDBBPSZ){
        kdbp("Failed(R) to install bp:%x at:0x%lx domid:%d\n",
             idx, kdb_sbpa[idx].bp_addr, domid);
        return 0;
    }
    if (kdb_write_mem(addr, &kdb_bpinst, KDBBPSZ, domid) != KDBBPSZ) {
        kdbp("Failed(W) to install bp:%x at:0x%lx domid:%d\n",
             idx, kdb_sbpa[idx].bp_addr, domid);
        return 0;
    }
    KDBGP("install_swbp: installed bp:%x at:0x%lx ccpu:%x domid:%d\n",
          idx, kdb_sbpa[idx].bp_addr, smp_processor_id(), domid);
    return 1;
}

/*
 * Install all the software breakpoints
 */
void
kdb_install_all_swbp(void)
{
    int i;
    for(i=0; i < KDBMAXSBP; i++)
        if (!kdb_sbpa[i].bp_deleted && kdb_sbpa[i].bp_addr)
            kdb_install_swbp(i);
}

static void
kdb_uninstall_a_swbp(int i)
{
    kdbva_t addr = kdb_sbpa[i].bp_addr;
    kdbbyt_t originst = kdb_sbpa[i].bp_originst;
    domid_t id = kdb_sbpa[i].bp_domid;

    kdb_sbpa[i].bp_just_added = 0;
    if (!addr)
        return;
    if (kdb_write_mem(addr, &originst, KDBBPSZ, id) != KDBBPSZ) {
        kdbp("Failed to uninstall breakpoint %x at:0x%lx domid:%d\n",
             i, kdb_sbpa[i].bp_addr, id);
    }
}

/*
 * Uninstall all the software breakpoints at beginning of kdb session
 */
void
kdb_uninstall_all_swbp(void)
{
    int i;
    for(i=0; i < KDBMAXSBP; i++) 
        kdb_uninstall_a_swbp(i);
    KDBGP("ccpu:%d uninstalled all bps\n", smp_processor_id());
}

/* RETURNS: rc == 2: condition was not met,  rc == 3: condition was met */
static int
kdb_check_bp_condition(int bpnum, struct cpu_user_regs *regs, domid_t domid)
{
    ulong res = 0, lhsval=0;
    struct kdb_bpcond *bpcp = &kdb_sbpa[bpnum].u.bp_cond;

    if (bpcp->bp_cond_status == 1) {             /* register condition */
        uint64_t *rp = (uint64_t *)((char *)regs + bpcp->bp_cond_lhs);
        lhsval = *rp;
    } else if (bpcp->bp_cond_status == 2) {      /* memaddr condition */
        ulong addr = bpcp->bp_cond_lhs;
        int num = sizeof(lhsval);

        if (kdb_read_mem(addr, (kdbbyt_t *)&lhsval, num, domid) != num) {
            kdbp("kdb: unable to read %d bytes at %lx\n", num, addr);
            return 3;
        }
    }
    if (bpcp->bp_cond_type == 1)                 /* lhs == rhs */
        res = (lhsval == bpcp->bp_cond_rhs);
    else                                         /* lhs != rhs */
        res = (lhsval != bpcp->bp_cond_rhs);

    if (!res)
        kdbp("KDB: [%d]Ignoring bp:%d condition not met. val:%lx\n", 
              smp_processor_id(), bpnum, lhsval); 

    KDBGP1("bpnum:%d domid:%d cond: %d %d %lx %lx res:%d\n", bpnum, domid, 
           bpcp->bp_cond_status, bpcp->bp_cond_type, bpcp->bp_cond_lhs, 
           bpcp->bp_cond_rhs, res);

    return (res ? 3 : 2);
}

static void
kdb_prnt_btp_info(int bpnum, struct cpu_user_regs *regs, domid_t domid)
{
    ulong i, arg, val, num, *btp = kdb_sbpa[bpnum].u.bp_btp;

    kdb_prnt_addr2sym(domid, regs->KDBIP, "\n");
    num = kdb_guest_bitness(domid)/8;
    for (i=0; i < KDB_MAXBTP && (arg=btp[i]); i++) {
        if (arg < sizeof (struct cpu_user_regs)) {
            uint64_t *rp = (uint64_t *)((char *)regs + arg);
            kdbp(" %s: %016lx ", kdb_regoffs_to_name(arg), *rp);
        } else {
            if (kdb_read_mem(arg, (kdbbyt_t *)&val, num, domid) != num)
                kdbp("kdb: unable to read %d bytes at %lx\n", num, arg);
            if (num == 8)
                kdbp(" %016lx:%016lx ", arg, val);
            else
                kdbp(" %08lx:%08lx ", arg, val);
        }
    }
    kdbp("\n");
    KDBGP1("bpnum:%d domid:%d btp:%p num:%d\n", bpnum, domid, btp, num);
}

/*
 * Check if the BP trap belongs to us. 
 * Return: 0 : not one of ours. IP not changed. (leave kdb)
 *         1 : one of ours but deleted. IP decremented. (leave kdb)
 *         2 : one of ours but condition not met, or btp. IP decremented.(leave)
 *         3 : one of ours and active. IP decremented. (stay in kdb)
 */
int 
kdb_check_sw_bkpts(struct cpu_user_regs *regs)
{
    int i, rc=0;
    domid_t curid;

    curid = guest_mode(regs) ? current->domain->domain_id : DOMID_IDLE;
    for(i=0; i < KDBMAXSBP; i++) {
        if (kdb_sbpa[i].bp_domid == curid  && 
            kdb_sbpa[i].bp_addr == (regs->KDBIP- KDBBPSZ)) {

            regs->KDBIP -= KDBBPSZ;
            rc = 3;

            if (kdb_sbpa[i].bp_ni) {
                kdb_uninstall_a_swbp(i);
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
            } else if (kdb_sbpa[i].bp_deleted) {
                rc = 1;
            } else if (kdb_sbpa[i].bp_type == 1) {
                rc = kdb_check_bp_condition(i, regs, curid);
            } else if (kdb_sbpa[i].bp_type == 2) {
                kdb_prnt_btp_info(i, regs, curid);
                rc = 2;
            }
            KDBGP1("ccpu:%d rc:%d curid:%d domid:%d addr:%lx\n", 
                   smp_processor_id(), rc, curid, kdb_sbpa[i].bp_domid, 
                   kdb_sbpa[i].bp_addr);
            break;
        }
    }
    return (rc);
}

/* Eg: r6 == 0x123EDF  or 0xFFFF2034 != 0xDEADBEEF
 * regoffs: -1 means lhs is not reg. else offset of reg in cpu_user_regs
 * addr: memory location if lhs is not register, eg, 0xFFFF2034
 * condp : points to != or ==
 * rhsval : right hand side value
 */
static void
kdb_set_bp_cond(int bpnum, int regoffs, ulong addr, char *condp, ulong rhsval)
{
    if (bpnum >= KDBMAXSBP) {
        kdbp("BUG: %s got invalid bpnum\n", __FUNCTION__);
        return;
    }
    if (regoffs != -1) {
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_status = 1;
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_lhs = regoffs;
    } else if (addr != 0) {
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_status = 2;
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_lhs = addr;
    } else {
        kdbp("error: invalid call to kdb_set_bp_cond\n");
        return;
    }
    kdb_sbpa[bpnum].u.bp_cond.bp_cond_rhs = rhsval;

    if (*condp == '!')
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_type = 2;
    else
        kdb_sbpa[bpnum].u.bp_cond.bp_cond_type = 1;
}

/* install breakpt at given addr. 
 * ni: bp for next instr 
 * btpa: ptr to args for btp for printing when bp is hit
 * lhsp/condp/rhsp: point to strings of condition
 *
 * RETURNS: the index in array where installed. KDBMAXSBP if error 
 */
static int
kdb_set_bp(domid_t domid, kdbva_t addr, int ni, ulong *btpa, char *lhsp, 
           char *condp, char *rhsp)
{
    int i, pre_existing = 0, regoffs = -1;
    ulong memloc=0, rhsval=0, tmpul;

    if (btpa && (lhsp || rhsp || condp)) {
        kdbp("internal error. btpa and (lhsp || rhsp || condp) set\n");
        return KDBMAXSBP;
    }
    if (lhsp && ((regoffs=kdb_valid_reg(lhsp)) == -1)  &&
        kdb_str2ulong(lhsp, &memloc) &&
        kdb_read_mem(memloc, (kdbbyt_t *)&tmpul, sizeof(tmpul), domid)==0) {

        kdbp("error: invalid argument: %s\n", lhsp);
        return KDBMAXSBP;
    }
    if (rhsp && ! kdb_str2ulong(rhsp, &rhsval)) {
        kdbp("error: invalid argument: %s\n", rhsp);
        return KDBMAXSBP;
    }

    /* see if bp already set */
    for (i=0; i < KDBMAXSBP; i++) {
        if (kdb_sbpa[i].bp_addr==addr && kdb_sbpa[i].bp_domid==domid) {

            if (kdb_sbpa[i].bp_deleted) {
                /* just re-set this bp again */
                memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
                pre_existing = 1;
            } else {
                kdbp("Breakpoint already set \n");
                return KDBMAXSBP;
            }
        }
    }
    /* see if any room left for another breakpoint */
    for (i=0; i < KDBMAXSBP; i++)
        if (!kdb_sbpa[i].bp_addr)
            break;
    if (i >= KDBMAXSBP) {
        kdbp("ERROR: Breakpoint table full....\n");
        return i;
    }
    kdb_sbpa[i].bp_addr = addr;
    kdb_sbpa[i].bp_domid = domid;
    if (btpa) {
        kdb_sbpa[i].bp_type = 2;
        kdb_sbpa[i].u.bp_btp = btpa;
    } else if (regoffs != -1 || memloc) {
        kdb_sbpa[i].bp_type = 1;
        kdb_set_bp_cond(i, regoffs, memloc, condp, rhsval);
    } else
        kdb_sbpa[i].bp_type = 0;

    if (kdb_install_swbp(i)) {                  /* make sure it can be done */
        if (ni)
            return i;

        kdb_uninstall_a_swbp(i);                /* dont' show user INT3 */
        if (!pre_existing)               /* make sure no is cpu sitting on it */
            kdb_sbpa[i].bp_just_added = 1;

        kdbp("bp %d set for domid:%d at: 0x%lx ", i, kdb_sbpa[i].bp_domid, 
             kdb_sbpa[i].bp_addr);
        kdb_prnt_addr2sym(domid, addr, "\n");
        kdb_prnt_bp_extra(i);
    } else {
        kdbp("ERROR:Can't install bp: 0x%lx domid:%d\n", addr, domid);
        if (pre_existing)     /* in case a cpu is sitting on this bp in traps */
            kdb_sbpa[i].bp_deleted = 1;
        else
            memset(&kdb_sbpa[i], 0, sizeof(kdb_sbpa[i]));
        return KDBMAXSBP;
    }
    /* make sure swbp reporting is enabled in the vmcb/vmcs */
    if (!is_pv_domain(kdb_domid2ptr(domid))) {
        struct domain *dp = kdb_domid2ptr(domid);
        dp->debugger_attached = 1;              /* see svm_do_resume/vmx_do_ */
        KDBGP("debugger_attached set. domid:%d\n", domid);
    }
    return i;
}

/* 
 * Set/List Software Breakpoint/s
 */
static kdb_cpu_cmd_t
kdb_usgf_bp(void)
{
    kdbp("bp [addr|sym][domid][condition]: display or set a breakpoint\n");
    kdbp("  where cond is like: r6 == 0x123F or rax != DEADBEEF or \n");
    kdbp("       ffff82c48038fe58 == 321E or 0xffff82c48038fe58 != 0\n");
    kdbp("  regs: rax rbx rcx rdx rsi rdi rbp rsp r8 r9");
    kdbp(" r10 r11 r12 r13 r14 r15 rflags\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_bp(int argc, const char **argv, struct cpu_user_regs *regs)
{
    kdbva_t addr;
    int idx = -1;
    domid_t domid = DOMID_IDLE;
    char *domidstrp, *lhsp=NULL, *condp=NULL, *rhsp=NULL;

    if ((argc > 1 && *argv[1] == '?') || argc == 4 || argc > 6)
        return kdb_usgf_bp();

    if (argc < 2 || kdb_sys_crash)         /* list all set breakpoints */
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
    domidstrp = (argc == 3 || argc == 6 ) ? (char *)argv[2] : NULL;
    if (domidstrp && !kdb_str2domid(domidstrp, &domid, 1)) {
        return kdb_usgf_bp();
    }
    if (argc > 3 && !is_pv_domain(kdb_domid2ptr(domid))) {
        kdbp("HVM domain not supported yet for conditional bp\n");
        return KDB_CPU_MAIN_KDB;
    }

    if (!kdb_str2addr(argv[1], &addr, domid) || addr == 0) {
        kdbp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }

    /* make sure xen addr is in xen text, otherwise bp set in 64bit dom0/U */
    if (domid == DOMID_IDLE && 
        (addr < XEN_VIRT_START || addr > XEN_VIRT_END))
    {
        kdbp("addr:%lx not in  xen text\n", addr);
        return KDB_CPU_MAIN_KDB;
    }
    kdb_set_bp(domid, addr, 0, NULL, lhsp, condp, rhsp);     /* 0 is ni flag */
    return KDB_CPU_MAIN_KDB;
}


/* trace breakpoint, meaning, upon bp trace/print some info and continue */

static kdb_cpu_cmd_t
kdb_usgf_btp(void)
{
    kdbp("btp addr|sym [domid] reg|domid-mem-addr... : breakpoint trace\n");
    kdbp("  regs: rax rbx rcx rdx rsi rdi rbp rsp r8 r9 ");
    kdbp("r10 r11 r12 r13 r14 r15 rflags\n");
    kdbp("  Eg. btp idle_cpu 7 rax rbx 0x20ef5a5 r9\n");
    kdbp("      will print rax, rbx, *(long *)0x20ef5a5, r9 and continue\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_btp(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int i, btpidx, numrd, argsidx, regoffs = -1;
    kdbva_t addr, memloc=0;
    domid_t domid = DOMID_IDLE;
    ulong *btpa, tmpul;

    if ((argc > 1 && *argv[1] == '?') || argc < 3)
        return kdb_usgf_btp();

    argsidx = 2;                   /* assume 3rd arg is not domid */
    if (argc > 3 && kdb_str2domid(argv[2], &domid, 0)) {

        if (!is_pv_domain(kdb_domid2ptr(domid))) {
            kdbp("HVM domains are not currently supprted\n");
            return KDB_CPU_MAIN_KDB;
        } else
            argsidx = 3;               /* 3rd arg is a domid */
    }
    if (!kdb_str2addr(argv[1], &addr, domid) || addr == 0) {
        kdbp("Invalid argument:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    /* make sure xen addr is in xen text, otherwise will trace 64bit dom0/U */
    if (domid == DOMID_IDLE && 
        (addr < XEN_VIRT_START || addr > XEN_VIRT_END))
    {
        kdbp("addr:%lx not in  xen text\n", addr);
        return KDB_CPU_MAIN_KDB;
    }

    numrd = kdb_guest_bitness(domid)/8;
    if (kdb_read_mem(addr, (kdbbyt_t *)&tmpul, numrd, domid) != numrd) {
        kdbp("Unable to read mem from %s (%lx)\n", argv[1], addr);
        return KDB_CPU_MAIN_KDB;
    }

    for (btpidx=0; btpidx < KDBMAXSBP && kdb_btp_ap[btpidx]; btpidx++);
    if (btpidx >= KDBMAXSBP) {
        kdbp("error: table full. delete few breakpoints\n");
        return KDB_CPU_MAIN_KDB;
    }
    btpa = kdb_btp_argsa[btpidx];
    memset(btpa, 0, sizeof(kdb_btp_argsa[0]));

    for (i=0; argv[argsidx]; i++, argsidx++) {

        if (((regoffs=kdb_valid_reg(argv[argsidx])) == -1)  &&
            kdb_str2ulong(argv[argsidx], &memloc) &&
            (memloc < sizeof (struct cpu_user_regs) ||
            kdb_read_mem(memloc, (kdbbyt_t *)&tmpul, sizeof(tmpul), domid)==0)){

            kdbp("error: invalid argument: %s\n", argv[argsidx]);
            return KDB_CPU_MAIN_KDB;
        }
        if (i >= KDB_MAXBTP) {
            kdbp("error: cannot specify more than %d args\n", KDB_MAXBTP);
            return KDB_CPU_MAIN_KDB;
        }
        btpa[i] = (regoffs == -1) ? memloc : regoffs;
    }

    i = kdb_set_bp(domid, addr, 0, btpa, 0, 0, 0);     /* 0 is ni flag */
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
static kdb_cpu_cmd_t
kdb_usgf_wp(void)
{
    kdbp("wp [addr|sym][w|i]: display or set watchpoint. writeonly or IO\n");
    kdbp("\tnote: watchpoint is triggered after the instruction executes\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_wp(int argc, const char **argv, struct cpu_user_regs *regs)
{
    kdbva_t addr;
    domid_t domid = DOMID_IDLE;
    int rw = 3, len = 4;       /* for now just default to 4 bytes len */

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_wp();

    if (argc <= 1 || kdb_sys_crash) {       /* list all set watchpoints */
        kdb_do_watchpoints(0, 0, 0);
        return KDB_CPU_MAIN_KDB;
    }
    if (!kdb_str2addr(argv[1], &addr, domid) || addr == 0) {
        kdbp("Invalid argument:%s\n", argv[1]);
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
    kdb_do_watchpoints(addr, rw, len);
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_wc(void)
{
    kdbp("wc $num|all : clear given or all watchpoints\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_wc(int argc, const char **argv, struct cpu_user_regs *regs)
{
    const char *argp;
    int wpnum;              /* wp num to delete. -1 for all */

    if (argc != 2 || *argv[1] == '?') 
        return kdb_usgf_wc();

    argp = argv[1];

    if (!strcmp(argp, "all"))
        wpnum = -1;
    else if (!kdb_str2deci(argp, &wpnum)) {
        kdbp("Invalid wpnum: %s\n", argp);
        return KDB_CPU_MAIN_KDB;
    }
    kdb_clear_wps(wpnum);
    return KDB_CPU_MAIN_KDB;
}

static void
kdb_display_hvm_vcpu(struct vcpu *vp)
{
    struct hvm_vcpu *hvp = &vp->arch.hvm_vcpu;
    struct vlapic *vlp = &hvp->vlapic;
    struct hvm_io_op *ioop;

    kdbp("vcpu:%lx id:%d domid:%d\n", vp, vp->vcpu_id, vp->domain->domain_id);

    ioop = NULL;   /* compiler warning */
    kdbp("    &hvm_vcpu:%lx  guest_efer:"KDBFL"\n", hvp, hvp->guest_efer);
    kdbp("      guest_cr: [0]:"KDBFL" [1]:"KDBFL" [2]:"KDBFL"\n", 
         hvp->guest_cr[0], hvp->guest_cr[1],hvp->guest_cr[2]);
    kdbp("                [3]:"KDBFL" [4]:"KDBFL"\n", hvp->guest_cr[3],
         hvp->guest_cr[4]);
    kdbp("      hw_cr: [0]:"KDBFL" [1]:"KDBFL" [2]:"KDBFL"\n", hvp->hw_cr[0],
         hvp->hw_cr[1], hvp->hw_cr[2]);
    kdbp("              [3]:"KDBFL" [4]:"KDBFL"\n", hvp->hw_cr[3], 
         hvp->hw_cr[4]);

    kdbp("      VLAPIC: base msr:"KDBF64" dis:%x tmrdiv:%x\n", 
         vlp->hw.apic_base_msr, vlp->hw.disabled, vlp->hw.timer_divisor);
    kdbp("          regs:%p regs_page:%p\n", vlp->regs, vlp->regs_page);
    kdbp("          periodic time:\n"); 
    kdb_prnt_periodic_time(&vlp->pt);

#if 0
    kdbp("      xen_port:%x flag_dr_dirty:%x dbg_st_latch:%x\n", hvp->xen_port,
         hvp->flag_dr_dirty, hvp->debug_state_latch);
#endif


#if XEN_VERSION == 4 && XEN_SUBVERSION > 2 
    {
    struct nestedvcpu *nvp = &hvp->nvcpu;

    kdbp("    Nested: nestedvcpu:%p nv_guestmode:%d\n", nvp, nvp->nv_guestmode);
    kdbp("        pending: vmentry:%d vmexit:%d vmswitch:%d\n",
         nvp->nv_vmentry_pending, nvp->nv_vmexit_pending,
         nvp->nv_vmswitch_in_progress);
    }
#endif /* #if XEN_SUBVERSION > 4 || XEN_VERSION == 4 */

    if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {

        struct arch_vmx_struct *vxp = &hvp->u.vmx;
        kdbp("      &vmx: %p vmcs:%lx active_cpu:%x launched:%x\n", vxp, 
             vxp->vmcs, vxp->active_cpu, vxp->launched);
#if XEN_VERSION != 4               /* xen 3.x.x */
        kdbp("        exec_ctrl:%x vpid:$%d\n", vxp->exec_control, vxp->vpid);
#endif
        kdbp("      host_cr0: "KDBFL" vmx: {realm:%x emulate:%x segmask:%x}\n",
             vxp->host_cr0, vxp->vmx_realmode, vxp->vmx_emulate,
             vxp->vm86_segment_mask);

#ifdef __x86_64__
        kdbp("       &msr_state:%p exception_bitmap:%lx\n", &vxp->msr_state,
             vxp->exception_bitmap);
#endif
    } else if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
        struct arch_svm_struct *svp = &hvp->u.svm;
#if XEN_VERSION != 4               /* xen 3.x.x */
        kdbp("  &svm: vmcb:%lx pa:"KDBF64" asid:"KDBF64"\n", svp, svp->vmcb,
             svp->vmcb_pa, svp->asid_generation);
#endif
        kdbp("    msrpm:%p lnch_core:%x vmcb_sync:%x\n", svp->msrpm, 
             svp->launch_core, svp->vmcb_in_sync);
    }
#if XEN_VERSION == 4 && XEN_SUBVERSION > 2 
    kdbp("      cachemode:%x io: {state: %x data: "KDBFL"}\n", hvp->cache_mode,
         hvp->hvm_io.io_state, hvp->hvm_io.io_data);
    kdbp("      mmio: {gva: "KDBFL" gpfn: "KDBFL"}\n", hvp->hvm_io.mmio_gva,
         hvp->hvm_io.mmio_gpfn);
#endif
}

/* display struct hvm_vcpu{} in struct vcpu.arch{} */
static kdb_cpu_cmd_t
kdb_usgf_vcpuh(void)
{
    kdbp("vcpuh vcpu-ptr : display hvm_vcpu struct\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_vcpuh(int argc, const char **argv, struct cpu_user_regs *regs)
{
    struct vcpu *vp;

    if (argc < 2 || *argv[1] == '?') 
        return kdb_usgf_vcpuh();

    if (!kdb_str2ulong(argv[1], (ulong *)&vp) || !kdb_vcpu_valid(vp) ||
        is_pv_vcpu(vp)) {

        kdbp("kdb: Bad VCPU: %s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    kdb_display_hvm_vcpu(vp);
    return KDB_CPU_MAIN_KDB;
}

/* also look into arch_get_info_guest() to get context */
static void
kdb_print_uregs(struct cpu_user_regs *regs)
{
#ifdef __x86_64__
    kdbp("      rflags: %016lx   rip: %016lx\n", regs->rflags, regs->rip);
    kdbp("         rax: %016lx   rbx: %016lx   rcx: %016lx\n",
         regs->rax, regs->rbx, regs->rcx);
    kdbp("         rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
         regs->rdx, regs->rsi, regs->rdi);
    kdbp("         rbp: %016lx   rsp: %016lx    r8: %016lx\n",
         regs->rbp, regs->rsp, regs->r8);
    kdbp("          r9:  %016lx  r10: %016lx   r11: %016lx\n",
         regs->r9,  regs->r10, regs->r11);
    kdbp("         r12: %016lx   r13: %016lx   r14: %016lx\n",
         regs->r12, regs->r13, regs->r14);
    kdbp("         r15: %016lx\n", regs->r15);
    kdbp("      ds: %04x   es: %04x   fs: %04x   gs: %04x   "
         "      ss: %04x   cs: %04x\n", regs->ds, regs->es, regs->fs,
         regs->gs, regs->ss, regs->cs);
    kdbp("      errcode:%08lx entryvec:%08lx upcall_mask:%lx\n",
         regs->error_code, regs->entry_vector, regs->saved_upcall_mask);
#else
    kdbp("      eflags: %016lx eip: 016lx\n", regs->eflags, regs->eip);
    kdbp("      eax: %08x   ebx: %08x   ecx: %08x   edx: %08x\n",
         regs->eax, regs->ebx, regs->ecx, regs->edx);
    kdbp("      esi: %08x   edi: %08x   ebp: %08x   esp: %08x\n",
         regs->esi, regs->edi, regs->ebp, regs->esp);
    kdbp("      ds: %04x   es: %04x   fs: %04x   gs: %04x   "
     "      ss: %04x   cs: %04x\n", regs->ds, regs->es, regs->fs,
         regs->gs, regs->ss, regs->cs);
    kdbp("      errcode:%04lx entryvec:%04lx upcall_mask:%lx\n", 
         regs->error_code, regs->entry_vector, regs->saved_upcall_mask);
#endif
}

#if XEN_SUBVERSION < 3             /* xen 3.1.x or xen 3.2.x */
#ifdef CONFIG_COMPAT
    #undef vcpu_info
    #define vcpu_info(v, field)             \
    (*(!has_32bit_shinfo((v)->domain) ?                                       \
       (typeof(&(v)->vcpu_info->compat.field))&(v)->vcpu_info->native.field : \
       (typeof(&(v)->vcpu_info->compat.field))&(v)->vcpu_info->compat.field))

    #undef __shared_info
    #define __shared_info(d, s, field)                      \
    (*(!has_32bit_shinfo(d) ?                           \
       (typeof(&(s)->compat.field))&(s)->native.field : \
       (typeof(&(s)->compat.field))&(s)->compat.field))
#endif
#endif

static void kdb_display_pv_vcpu(struct vcpu *vp)
{
    int i;
#if XEN_VERSION == 4 && XEN_SUBVERSION < 4 
    struct vcpu_guest_context *gp = &vp->arch.guest_context;
#else
    struct pv_vcpu *gp = &vp->arch.pv_vcpu;
#endif

    kdbp("      GDT_VIRT_START(vcpu): %lx\n", GDT_VIRT_START(vp));
    kdbp("      GDT: entries:0x%lx  frames:\n", gp->gdt_ents);
    for (i=0; i < FIRST_RESERVED_GDT_PAGE; i++) 
        if (  gp->gdt_frames[i] )
            kdbp("         %d:%016lx ", i, gp->gdt_frames[i]); 
    kdbp("\n");

    kdbp("      trap_ctxt:%lx kernel_ss:%lx kernel_sp:%lx\n", gp->trap_ctxt,
         gp->kernel_ss, gp->kernel_sp);
    kdbp("      ctrlregs:\n");
    for (i=0; i < 8; i=i+4)
        kdbp("          %016lx %016lx %016lx %016lx\n", gp->ctrlreg[i], 
             gp->ctrlreg[i+1], gp->ctrlreg[i+2], gp->ctrlreg[i+3]);
#ifdef __x86_64__
    kdbp("      callback:   event: %016lx   failsafe: %016lx\n", 
         gp->event_callback_eip, gp->failsafe_callback_eip);
    kdbp("      base: fs:%lx gskern:%lx gsuser:%lx\n", 
         gp->fs_base, gp->gs_base_kernel, gp->gs_base_user);
#else
    kdbp("      callback:   event: %08lx:%08lx   failsafe: %08lx:%08lx\n", 
         gp->event_callback_cs, gp->event_callback_eip, 
         gp->failsafe_callback_cs, gp->failsafe_callback_eip);
#endif
    kdbp("\n");
}

static char *
kdb_prnt_tstatus(int status)
{
    switch (status)
    {
        case 0: return "TIMER_STATUS_invalid";
        case 1: return "TIMER_STATUS_inactive";
        case 2: return "TIMER_STATUS_killed";
        case 3: return "TIMER_STATUS_in_heap";
        case 4: return "TIMER_STATUS_in_list";
        default: return "????";
    }
}

static void
kdb_print_timer(struct timer *tp, char *name)
{
    kdbp("\n");
    kdbp("    TIMER: %s\n", name);
    kdbp("        expires:%016lx fn:%016lx data:%016lx\n", 
         tp->expires, tp->function, tp->data);
    kdbp("        status:%d (%s)\n", tp->status, kdb_prnt_tstatus(tp->status));
    kdbp("\n");
}

/* Display one VCPU info */
static void
kdb_display_vcpu(struct vcpu *vp)
{
    int i;
    struct arch_vcpu *avp = &vp->arch;
    struct paging_vcpu *pvp = &vp->arch.paging;
    int domid = vp->domain->domain_id;

    kdbp("\nVCPU:  vcpu-id:%d  vcpu-ptr:%p ", vp->vcpu_id, vp);
    kdbp("  processor:%d domid:%d  domp:%p\n", vp->processor, domid,vp->domain);

    if (domid == DOMID_IDLE) {
        kdbp("    IDLE vcpu.\n");
        return;
    }
    kdbp("  pause: flags:0x%016lx count:%x\n", vp->pause_flags, 
         vp->pause_count.counter);
    kdbp("  vcpu: initdone:%d running:%d\n", 
         vp->is_initialised, vp->is_running);
    kdbp("  mcepend:%d nmipend:%d shut: def:%d paused:%d\n", 
         vp->mce_pending,  vp->nmi_pending, vp->defer_shutdown, 
         vp->paused_for_shutdown);
    kdbp("  &vcpu_info:%p : evtchn_upc_pend:%x _mask:%x\n",
         vp->vcpu_info, vcpu_info(vp, evtchn_upcall_pending),
         vcpu_info(vp, evtchn_upcall_mask));
    kdbp("  evt_pend_sel:%lx poll_evtchn:%x ", 
         *(unsigned long *)&vcpu_info(vp, evtchn_pending_sel), vp->poll_evtchn);
    kdb_print_spin_lock("virq_lock:", &vp->virq_lock, "\n");
    for (i=0; i < NR_VIRQS; i++)
        if (vp->virq_to_evtchn[i] != 0)
            kdbp("      virq:$%d port:$%d\n", i, vp->virq_to_evtchn[i]);

    kdbp("  next:%p periodic: period:0x%lx last_event:0x%lx\n", 
         vp->next_in_list, vp->periodic_period, vp->periodic_last_event);

    kdb_print_timer(&vp->periodic_timer, "periodic_timer");
    kdb_print_timer(&vp->singleshot_timer, "singleshot_timer");

#if XEN_VERSION == 4 && XEN_SUBVERSION < 5 
     kdbp("  vcpu_dirty_cpumask:%p sched_priv:0x%p\n",
          vp->vcpu_dirty_cpumask, vp->sched_priv);
#else
    kdbp("  cpu_affinity:0x%lx vcpu_dirty_cpumask:%p sched_priv:0x%p\n",
         vp->cpu_hard_affinity, vp->vcpu_dirty_cpumask, vp->sched_priv);
#endif
    kdbp("  &runstate: %p state: %x (eg. RUNSTATE_running)\n", 
         &vp->runstate, vp->runstate.state);
    kdbp("  runstate_guestptr:%p", runstate_guest(vp));
#if XEN_VERSION >= 4 && XEN_SUBVERSION > 1   /* xen 4.2.x or above */
    kdbp("  vcpu_info_mfn:%lx\n", vp->vcpu_info_mfn);
    kdbp("\n");
    kdbp("  arch info: (%p)\n", &vp->arch);
    kdbp("    guest_context: VGCF_ flags:%lx", 
         vp->arch.vgc_flags); /* VGCF_in_kernel */
    if (!is_pv_vcpu(vp))
        kdbp("    (HVM guest: IP, SP, EFLAGS may be stale)");
    kdbp("\n");
    kdb_print_uregs(&vp->arch.user_regs);
    kdbp("      debugregs:\n");
    for (i=0; i < 8; i=i+4)
        kdbp("          %016lx %016lx %016lx %016lx\n", avp->debugreg[i], 
             avp->debugreg[i+1], avp->debugreg[i+2], avp->debugreg[i+3]);
#else
    kdbp("\n\n");
#endif
    if (is_pv_vcpu(vp))
        kdb_display_pv_vcpu(vp);
    else
        kdb_display_hvm_vcpu(vp);

    kdbp("    TF_flags: %016lx  monitor_tbl:%lx\n",
         vp->arch.flags, vp->arch.monitor_table.pfn);
    kdbp("    guest_table: %016lx cr3:%016lx\n",
         vp->arch.guest_table.pfn, avp->cr3);
    kdbp("    paging: \n");
    kdbp("      vtlb:%p\n", &pvp->vtlb);
    kdbp("      &pg_mode:%p gstlevels:%d &shadow:%p shlevels:%d\n",
         pvp->mode, pvp->mode->guest_levels, &pvp->mode->shadow,
         pvp->mode->shadow.shadow_levels);
    kdbp("      shadow_vcpu:\n");
    kdbp("        guest_vtable:%p last em_mfn:"KDBFL"\n",
         pvp->shadow.guest_vtable, pvp->shadow.last_emulated_mfn);
#if CONFIG_PAGING_LEVELS >= 3
    kdbp("         l3tbl: 3:"KDBFL" 2:"KDBFL"\n"
         "                1:"KDBFL" 0:"KDBFL"\n",
     pvp->shadow.l3table[3].l3, pvp->shadow.l3table[2].l3, 
     pvp->shadow.l3table[1].l3, pvp->shadow.l3table[0].l3);
    kdbp("        gl3tbl: 3:"KDBFL" 2:"KDBFL"\n"
         "                1:"KDBFL" 0:"KDBFL"\n",
     pvp->shadow.gl3e[3].l3, pvp->shadow.gl3e[2].l3, 
     pvp->shadow.gl3e[1].l3, pvp->shadow.gl3e[0].l3);
#endif
    kdbp("  gdbsx_vcpu_event:%x\n", vp->arch.gdbsx_vcpu_event);
}

/* 
 * FUNCTION: Dispaly (current) VCPU/s
 */
static kdb_cpu_cmd_t
kdb_usgf_vcpu(void)
{
    kdbp("vcpu [vcpu-ptr] : display current/vcpu-ptr vcpu info\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_vcpu(int argc, const char **argv, struct cpu_user_regs *regs)
{
    struct vcpu *v = current;

    if (argc > 2 || (argc > 1 && *argv[1] == '?'))
        kdb_usgf_vcpu();
    else if (argc <= 1)
        kdb_display_vcpu(v);
    else if (kdb_str2ulong(argv[1], (ulong *)&v) && kdb_vcpu_valid(v))
        kdb_display_vcpu(v);
    else 
        kdbp("Invalid usage/argument:%s v:%lx\n", argv[1], (long)v);
    return KDB_CPU_MAIN_KDB;
}

/* from paging_dump_domain_info() */
static void kdb_pr_dom_pg_modes(struct domain *d)
{
    if (paging_mode_enabled(d)) {
        kdbp(" paging mode enabled");
        if ( paging_mode_shadow(d) )
            kdbp(" shadow(PG_SH_enable)");
        if ( paging_mode_hap(d) )
            kdbp(" hap(PG_HAP_enable) ");
        if ( paging_mode_refcounts(d) )
            kdbp(" refcounts(PG_refcounts) ");
        if ( paging_mode_log_dirty(d) )
            kdbp(" log_dirty(PG_log_dirty) ");
        if ( paging_mode_translate(d) )
            kdbp(" translate(PG_translate) ");
        if ( paging_mode_external(d) )
            kdbp(" external(PG_external) ");
    } else
        kdbp(" disabled");
    kdbp("\n");
}

static char *kdb_state_ecs_str(int state)
{
    switch (state)
    {
        case ECS_FREE:
            return "ECS_FREE";
        case ECS_RESERVED:
            return "ECS_RESERVED";
        case ECS_UNBOUND:
            return "ECS_UNBOUND";
        case ECS_INTERDOMAIN:
            return "ECS_INTERDOMAIN";
        case ECS_PIRQ:
            return "ECS_PIRQ";
        case ECS_VIRQ:
            return "ECS_VIRQ";
        case ECS_IPI:
            return "ECS_IPI";
        default:
            return "\0";
    }
    return "\0";
}

/* print event channels info for a given domain 
 * NOTE: very confusing, port and event channel refer to the same thing. evtchn
 * is arry of pointers to a bucket of pointers to 128 struct evtchn{}. while
 * 64bit xen can handle 4096 max channels, a 32bit guest is limited to 1024 */
static void noinline kdb_print_dom_eventinfo(struct domain *dp)
{
#if XEN_VERSION < 4 || XEN_SUBVERSION < 2     /* xen 4.1.x or before */
    extern void domain_dump_evtchn_info(struct domain *d);
    domain_dump_evtchn_info(dp);
#elif  XEN_VERSION > 3 && XEN_SUBVERSION > 3  /* xen 4.4 and above */
    uint port, pirq;

    /* for evtchn_port_ops, do 'x/g addr' in 'gdb xen-syms' */
    kdbp("Event channel info:\n");
    kdbp("  Evt: Port Ops: %p  MAX_NR_EVTCHNS:$%d ptr:%p \npollmsk:%016lx ",
         dp->evtchn_port_ops, MAX_NR_EVTCHNS, dp->evtchn, dp->poll_mask[0]);
    kdbp("    &evtchn_pending:%p &evtchn_mask:%p\n", 
         shared_info(dp, evtchn_pending), shared_info(dp, evtchn_mask));

    kdbp("   Channels/Ports info: (everything is in decimal):\n");
    for (port=0; port < MAX_NR_EVTCHNS; port++ ) {
        char pbit, mbit;
        struct evtchn *chnp;

        if ( !port_is_valid(dp, port) )
            continue;

        chnp = evtchn_from_port(dp,port);
        if ( chnp->state == ECS_FREE )
            continue;

        pbit = evtchn_port_is_pending(dp, port) ? 'Y' : 'N';
        mbit = evtchn_port_is_masked(dp, port) ? 'Y' : 'N';

        kdbp("   %2u st:%16s notify_v:%2d ", port, 
             kdb_state_ecs_str(chnp->state), chnp->notify_vcpu_id);

        if (chnp->state == ECS_UNBOUND)
            kdbp(" rem-domid:%d", chnp->u.unbound.remote_domid);
        else if (chnp->state == ECS_INTERDOMAIN)
            kdbp(" rem-port:%d rem-dom:%d", chnp->u.interdomain.remote_port,
                 chnp->u.interdomain.remote_dom->domain_id);
        else if (chnp->state == ECS_PIRQ)
            kdbp(" pirq:%d irq:%d", chnp->u.pirq.irq, 
                 domain_pirq_to_irq(dp, chnp->u.pirq.irq));
        else if (chnp->state == ECS_VIRQ)
            kdbp(" virq:%d", chnp->u.virq);

        kdbp("  pend:%c mask:%c\n", pbit, mbit);
    }

    kdbp("pirq to evtchn mapping (pirq:evtchn) (all decimal): nr_pirqs:%d\n",
         dp->nr_pirqs);
    for (pirq=0; pirq < dp->nr_pirqs; pirq++) {
        if (pirq_to_evtchn(dp, pirq) == 0)
            continue;
        kdbp("(%d:%d) ", pirq, pirq_to_evtchn(dp, pirq)); 
    }
    kdbp("\n");

#else /* XEN_VERSION */
    uint chn;

    kdbp("Event channel info:\n");
    kdbp("  Evt: MAX_NR_EVTCHNS:$%d ptr:%p pollmsk:%016lx ",
         MAX_NR_EVTCHNS, dp->evtchn, dp->poll_mask[0]);
    kdb_print_spin_lock("lk:", &dp->event_lock, "\n");
    kdbp("    &evtchn_pending:%p &evtchn_mask:%p\n", 
         shared_info(dp, evtchn_pending), shared_info(dp, evtchn_mask));

    kdbp("   Channels info: (everything is in decimal):\n");
    for (chn=0; chn < MAX_NR_EVTCHNS; chn++ ) {
        struct evtchn *bktp = &dp->evtchn[chn/EVTCHNS_PER_BUCKET];
        struct evtchn *chnp = &bktp[chn & (EVTCHNS_PER_BUCKET-1)];
        char pbit = test_bit(chn, &shared_info(dp, evtchn_pending)) ? 'Y' : 'N';
        char mbit = test_bit(chn, &shared_info(dp, evtchn_mask)) ? 'Y' : 'N';

        if (bktp==NULL || chnp->state==ECS_FREE)
            continue;

        kdbp("    chn:%4u st:%d _xen=%d _vcpu_id:%2d ", chn, chnp->state,
             chnp->xen_consumer, chnp->notify_vcpu_id);
        if (chnp->state == ECS_UNBOUND)
            kdbp(" rem-domid:%d", chnp->u.unbound.remote_domid);
        else if (chnp->state == ECS_INTERDOMAIN)
            kdbp(" rem-port:%d rem-dom:%d", chnp->u.interdomain.remote_port,
                 chnp->u.interdomain.remote_dom->domain_id);
        else if (chnp->state == ECS_PIRQ)
            kdbp(" pirq:%d", chnp->u.pirq);
        else if (chnp->state == ECS_VIRQ)
            kdbp(" virq:%d", chnp->u.virq);

        kdbp("  pend:%c mask:%c\n", pbit, mbit);
    }
#if 0
    kdbp("pirq to evtchn mapping (pirq:evtchn) (all decimal):\n");
    for (i=0; i < dp->nr_pirqs; i ++)
        if (dp->pirq_to_evtchn[i])
            kdbp("(%d:%d) ", i, dp->pirq_to_evtchn[i]);
    kdbp("\n");
#endif
#endif   /* #if XEN_VERSION */
}

static void kdb_prnt_hvm_dom_info(struct domain *dp)
{
    struct hvm_domain *hvp = &dp->arch.hvm_domain;

#if 0
    kdbp("    ioreq.page:%lx ioreq.va:%lx\n", hvp->ioreq.page, hvp->ioreq.va);
    kdbp("    buf_ioreq.page:%lx ioreq.va:%lx\n", hvp->buf_ioreq.page, 
         hvp->buf_ioreq.va);
#endif

    kdbp("    HVM info: Hap is%s enabled\n", 
         dp->arch.hvm_domain.hap_enabled ? "" : " not");

#if XEN_VERSION > 4 || XEN_SUBVERSION > 1       /* after xen 4.1.x */
    if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
        struct p2m_domain *p2m = p2m_get_hostp2m(dp);
        struct ept_data *ept = &p2m->ept;
        kdbp("    EPT: ept_mt:%x ept_wl:%x asr:%013lx\n", 
             ept->ept_mt, ept->ept_wl, ept->asr);
    }
#endif
    if (hvp == NULL)
        return;

    if (hvp->irq.callback_via_type == HVMIRQ_callback_vector)
        kdbp("    HVMIRQ_callback_vector: %x\n", hvp->irq.callback_via.vector);

    if (!hvp->params)
        return;

    kdbp("    HVM PARAMS (all in hex):\n");
    kdbp("\tHVM_PARAM_CALLBACK_IRQ: %x\n", hvp->params[HVM_PARAM_CALLBACK_IRQ]);
    kdbp("\tHVM_PARAM_STORE_PFN: %x\n", hvp->params[HVM_PARAM_STORE_PFN]);
    kdbp("\tHVM_PARAM_STORE_EVTCHN: %x\n", hvp->params[HVM_PARAM_STORE_EVTCHN]);
    kdbp("\tHVM_PARAM_PAE_ENABLED: %x\n", hvp->params[HVM_PARAM_PAE_ENABLED]);
    kdbp("\tHVM_PARAM_IOREQ_PFN: %x\n", hvp->params[HVM_PARAM_IOREQ_PFN]);
    kdbp("\tHVM_PARAM_BUFIOREQ_PFN: %x\n", hvp->params[HVM_PARAM_BUFIOREQ_PFN]);
    kdbp("\tHVM_PARAM_VIRIDIAN: %x\n", hvp->params[HVM_PARAM_VIRIDIAN]);
    kdbp("\tHVM_PARAM_TIMER_MODE: %x\n", hvp->params[HVM_PARAM_TIMER_MODE]);
    kdbp("\tHVM_PARAM_HPET_ENABLED: %x\n", hvp->params[HVM_PARAM_HPET_ENABLED]);
    kdbp("\tHVM_PARAM_IDENT_PT: %x\n", hvp->params[HVM_PARAM_IDENT_PT]);
    kdbp("\tHVM_PARAM_DM_DOMAIN: %x\n", hvp->params[HVM_PARAM_DM_DOMAIN]);
    kdbp("\tHVM_PARAM_ACPI_S_STATE: %x\n", hvp->params[HVM_PARAM_ACPI_S_STATE]);
    kdbp("\tHVM_PARAM_VM86_TSS: %x\n", hvp->params[HVM_PARAM_VM86_TSS]);
    kdbp("\tHVM_PARAM_VPT_ALIGN: %x\n", hvp->params[HVM_PARAM_VPT_ALIGN]);
    kdbp("\tHVM_PARAM_CONSOLE_PFN: %x\n", hvp->params[HVM_PARAM_CONSOLE_PFN]);
    kdbp("\tHVM_PARAM_CONSOLE_EVTCHN: %x\n", 
         hvp->params[HVM_PARAM_CONSOLE_EVTCHN]);
    kdbp("\tHVM_PARAM_ACPI_IOPORTS_LOCATION: %x\n", 
         hvp->params[HVM_PARAM_ACPI_IOPORTS_LOCATION]);
    kdbp("\tHVM_PARAM_MEMORY_EVENT_SINGLE_STEP: %x\n", 
         hvp->params[HVM_PARAM_MEMORY_EVENT_SINGLE_STEP]);
}
static void kdb_print_rangesets(struct domain *dp)
{
    int locked = spin_is_locked(&dp->rangesets_lock);

    if (locked)
        spin_unlock(&dp->rangesets_lock);
    rangeset_domain_printk(dp);
    if (locked)
        spin_lock(&dp->rangesets_lock);
}

static void kdb_pr_vtsc_info(struct arch_domain *ap)
{
    kdbp("    VTSC info: tsc_mode:%x  vtsc:%x  vtsc_last:%016lx\n", 
         ap->tsc_mode, ap->vtsc, ap->vtsc_last);
    kdbp("        vtsc_offset:%016lx tsc_khz:%08lx incarnation:%x\n", 
         ap->vtsc_offset, ap->vtsc_offset, ap->incarnation);
    kdbp("        vtsc_kerncount:%016lx _usercount:%016lx\n",
         ap->vtsc_kerncount, ap->vtsc_usercount);
}

static void kdb_print_p2mlock(struct domain *dp)
{
#if XEN_VERSION < 4 || XEN_SUBVERSION < 2     /* xen 4.1.x or before */
#else
    struct p2m_domain *p2m = p2m_get_hostp2m(dp);
    mm_rwlock_t *lp = p2m ? &p2m->lock : NULL;

    if (lp == NULL) {
        kdbp("    p2m lock ptr is null\n");
        return;
    }
    kdbp("    p2m lockval: %x unlock_level:%x recurse_count:%x locker cpu:%x\n",
         lp->lock, lp->unlock_level, lp->recurse_count, lp->locker);
    kdbp("    p2m locker_function:%s\n", lp->locker_function);
#endif  /* XEN_VERSION */
}

/* display one domain info */
static void
kdb_display_dom(struct domain *dp)
{
    struct vcpu *vp;
    int controller_pausecnt, printed = 0;
    struct grant_table *gp = dp->grant_table;
    struct arch_domain *ap = &dp->arch;

    kdbp("\nDOMAIN :    domid:0x%04x ptr:0x%p\n", dp->domain_id, dp);
    if (dp->domain_id == DOMID_IDLE) {
        kdbp("    IDLE domain.\n");
        return;
    }
    if (dp->is_dying) {
        kdbp("    domain is DYING.\n");
        return;
    }
#if XEN_VERSION >= 4  && XEN_SUBVERSION > 1 /* xen 4.2 and above */
    controller_pausecnt = dp->controller_pause_count;
#else
    controller_pausecnt = dp->is_paused_by_controller;
#endif
#if 0
    kdb_print_spin_lock("  pgalk:", &dp->page_alloc_lock, "\n");
    kdbp("  pglist:  0x%p 0x%p\n", dp->page_list.next,KDB_PGLLE(dp->page_list));
    kdbp("  xpglist: 0x%p 0x%p\n", dp->xenpage_list.next, 
         KDB_PGLLE(dp->xenpage_list));
    kdbp("  next:0x%p hashnext:0x%p\n", 
         dp->next_in_list, dp->next_in_hashbucket);
#endif
    kdbp("  PAGES: tot:0x%08x max:0x%08x xenheap:0x%08x\n", 
         dp->tot_pages, dp->max_pages, dp->xenheap_pages);

    kdb_print_rangesets(dp);
    kdb_print_dom_eventinfo(dp);
    kdbp("\n");
    kdbp("  Grant table: gp:0x%p\n", gp);
    if (gp) {
        kdbp("    nr_frames:0x%08x shpp:0x%p active:0x%p\n",
             gp->nr_grant_frames, gp->shared_raw, gp->active);
        kdbp("    maptrk:0x%p maplmt:0x%08x\n", 
             gp->maptrack, gp->maptrack_limit);
    }
    kdbp("  guest_type:%s priv:%d need_iommu:%d dbg:%d dying:%d cpausecnt:%d\n",
         is_hvm_domain(dp) ? "HVM" : "PV(or PVH)",
         dp->is_privileged, dp->need_iommu, dp->debugger_attached, dp->is_dying,
         controller_pausecnt);
    kdb_print_spin_lock("  shutdown: lk:", &dp->shutdown_lock, "\n");
    kdbp("  shutn:%d shut:%d code:%d \n", dp->is_shutting_down,
         dp->is_shut_down, dp->shutdown_code);
    kdbp("  pausecnt:0x%08x vm_assist:0x"KDBFL" refcnt:0x%08x\n",
         dp->pause_count.counter, dp->vm_assist, dp->refcnt.counter);
    kdbp("  &domain_dirty_cpumask:%p\n", &dp->domain_dirty_cpumask); 

    kdbp("  shared == vcpu_info[]: %p\n",  dp->shared_info); 
    kdbp("    arch_shared: maxpfn: %lx pfn-mfn-frame-ll mfn: %lx\n", 
         arch_get_max_pfn(dp), arch_get_pfn_to_mfn_frame_list_list(dp));
    kdbp("\n");

    if (!is_pv_domain(dp))
        kdb_prnt_hvm_dom_info(dp);
    kdbp("\n");

    kdbp("  arch_domain at : %p\n", ap);
    kdbp("    ioport:0x%p &hvm_dom:0x%p\n", ap->ioport_caps, &ap->hvm_domain);
    kdbp("    &pging_dom:%p mode: %lx", &ap->paging, ap->paging.mode); 
    kdb_pr_dom_pg_modes(dp);
    kdbp("    p2m ptr:%p  pages:{%p, %p}\n", ap->p2m, ap->p2m->pages.next,
         KDB_PGLLE(ap->p2m->pages));
    kdb_print_p2mlock(dp);
    kdbp("       max_mapped_pfn:"KDBFL, ap->p2m->max_mapped_pfn);
#if XEN_VERSION >= 4  && XEN_SUBVERSION > 0 /* xen 4.1 and above */
    kdbp("  phys_table:%p\n", ap->p2m->phys_table.pfn);
#else
    kdbp("  phys_table.pfn:"KDBFL"\n", ap->phys_table.pfn);
#endif
    kdbp("    physaddr_bitsz:%d 32bit_pv:%d has_32bit_shinfo:%d\n", 
         ap->physaddr_bitsize, ap->is_32bit_pv, ap->has_32bit_shinfo);
    kdb_pr_vtsc_info(ap);
    kdbp("  sched:0x%p  &handle:0x%p\n", dp->sched_priv, &dp->handle);
    kdbp("  vcpu ptrs:\n   ");
    for_each_vcpu(dp, vp) {
        kdbp(" %d:%p", vp->vcpu_id, vp);
        if (++printed % 4 == 0) kdbp("\n   ");
    }
    kdbp("\n");
}

/* 
 * FUNCTION: Dispaly (current) domain/s
 */
static kdb_cpu_cmd_t
kdb_usgf_dom(void)
{
    kdbp("dom [all|domid]: Display current/all/given domain/s\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t 
kdb_cmdf_dom(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int id;
    struct domain *dp = current->domain;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dom();

    if (argc > 1) {
        for(dp=domain_list; dp; dp=dp->next_in_list)
            if (kdb_str2deci(argv[1], &id) && dp->domain_id==id)
                kdb_display_dom(dp);
            else if (!strcmp(argv[1], "all")) 
                kdb_display_dom(dp);
    } else {
        kdbp("Displaying current domain :\n");
        kdb_display_dom(dp);
    }
    return KDB_CPU_MAIN_KDB;
}

#if XEN_VERSION < 4 && XEN_SUBVERSION < 5           /* xen 3.4.x or below */
static void kdb_dump_irq_34x_orless()
{
    kdbp("idx/irq#/status: all are in decimal\n");
    kdbp("idx  irq#  status   action(handler name devid)\n");
    for (irq=0; irq < NR_VECTORS; irq++) {
        irq_desc_t  *dp = &irq_desc[irq];
        if (!dp->action)
            continue;
        addr = (unsigned long)dp->action->handler;
        kdbp("[%3ld]:irq:%3d st:%3d f:%s devnm:%s devid:0x%p\n",
             irq, vector_to_irq(irq), dp->status, (dp->status & IRQ_GUEST) ? 
                            "GUEST IRQ" : symbols_lookup(addr, &sz, &offs, buf),
             dp->action->name, dp->action->dev_id);
    }
}
#endif
/* Dump irq desc table */
static kdb_cpu_cmd_t
kdb_usgf_dirq(void)
{
    kdbp("dirq : dump irq bindings\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_dirq(int argc, const char **argv, struct cpu_user_regs *regs)
{
    unsigned int irq, cpu;
    unsigned long sz, offs, addr;
    char buf[KSYM_NAME_LEN+1];
    char affstr[NR_CPUS/4+NR_CPUS/32+2];    /* courtesy dump_irqs() */

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dirq();

#if XEN_VERSION < 4 && XEN_SUBVERSION < 5           /* xen 3.4.x or below */
    kdb_dump_irq_34x_orless();
#elif XEN_VERSION == 4 && XEN_SUBVERSION < 2    /* xen 4.1.x */
    dump_irqs('0');
#else
    kdbp("irq_desc[irq]:%p nr_irqs: $%d nr_irqs_gsi: $%d\n", irq_desc, nr_irqs, 
          nr_irqs_gsi);
    kdbp("irq/vec#/status: decimal. affinity hex, not bitmap\n");
    kdbp("Xen: addr/symbol/name  Guest:domid/pirq/evtchn-port/notify-vcpu\n");

    //kdbp("irq#  vec affnty type--- owner-----------\n");
    kdbp("irq#  vec cpus affnty type--- owner-----------\n");
    for (irq=0; irq < nr_irqs; irq++) {
        char pbuf[8];
        const char *symp, *nmp;
        irq_desc_t  *desc = irq_to_desc(irq);
        int vector = irq_to_vector(irq);

        if ( vector <= 0 || !desc || !desc->handler)
            continue;

        pbuf[7] = '\0';
        memcpy(pbuf, desc->handler->typename, 7);

        cpumask_scnprintf(affstr, sizeof(affstr), desc->affinity);
        kdbp("[%3d] %3d ", irq, vector);
        for_each_present_cpu(cpu) {
            if (irq == per_cpu(vector_irq, cpu)[vector])
                kdbp("%d/", cpu);
        }
        kdbp(" ");
        kdbp("%s %-8s %s %s ", 
             affstr, pbuf, desc->status & IRQ_PER_CPU ? "IRQ_PER_CPU" : "",
             desc->status & IRQ_GUEST ? "Guest:" : "Xen:");
#if 0
        kdbp("[%3d] %3d %s %-8s %s %s ", 
             irq, vector, affstr, pbuf,
             desc->status & IRQ_PER_CPU ? "IRQ_PER_CPU" : "",
             desc->status & IRQ_GUEST ? "Guest:" : "Xen:");
#endif
        if (desc->status & IRQ_GUEST) {
            kdb_print_guest_irq_info(irq);  /* in arch/x86/irq.c */
        } else {
            struct irqaction *action = desc->action;

            if (action == NULL || action->handler == NULL) {
                kdbp("unbound\n");
                continue;
            }
            addr = action ? (unsigned long)action->handler : 0;
            symp = addr ? symbols_lookup(addr, &sz, &offs, buf) : "n/a ";
            nmp = addr ? action->name : "---- n/a ----";
            kdbp("%16lx/%s/%s\n", addr, symp, nmp);
        }
    }
#if 0
    kdbp("\nGuest mapped irqs:\n");
    kdb_prnt_guest_mapped_irqs();

    kdbp("irq_desc[]:%p nr_irqs: $%d nr_irqs_gsi: $%d\n", irq_desc, nr_irqs, 
          nr_irqs_gsi);
    kdbp("irq/vec#/status: in decimal. affinity in hex, not bitmap\n");
    kdbp("irq-- vec sta function----------- name---- type--------- ");
    kdbp("aff devid------------\n");
    for (irq=0; irq < nr_irqs; irq++) {
        void *devidp;
        const char *symp, *nmp;
        irq_desc_t  *dp = irq_to_desc(irq);
        struct arch_irq_desc *archp = &dp->arch;

        if (!dp->handler || dp->handler==&no_irq_type || dp->status & IRQ_GUEST)
            continue;

        addr = dp->action ? (unsigned long)dp->action->handler : 0;
        symp = addr ? symbols_lookup(addr, &sz, &offs, buf) : "n/a ";
        nmp = addr ? dp->action->name : "n/a ";
        devidp = addr ? dp->action->dev_id : NULL;
        cpumask_scnprintf(affstr, sizeof(affstr), dp->affinity);
        kdbp("[%3ld] %03d %03d %-19s %-8s %-13s %3s 0x%p\n", irq, archp->vector,
             dp->status, symp, nmp, dp->handler->typename, affstr, devidp);
    }
#endif

#endif /* XEN_VERSION */
    return KDB_CPU_MAIN_KDB;
}

static void kdb_prnt_vec_irq_table(int cpu)
{
    int vec,j, *tbl = per_cpu(vector_irq, cpu);

    kdbp("CPU %d : ", cpu);
    for (vec=0, j=0; vec < NR_VECTORS; vec++) {
        if (tbl[vec] == -1 || tbl[vec] == INT_MIN || tbl[vec] <= 0)
            continue;

        kdbp("(%3d:%3d) ", vec, tbl[vec]);
        if (!(++j % 5))
            kdbp("\n        ");
    }
    kdbp("\n");
}

/* Dump irq desc table */
static kdb_cpu_cmd_t kdb_usgf_dvit(void)
{
    kdbp("dvit [cpu|all]: dump (per cpu)vector irq table\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_dvit(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int vec, cpu, ccpu = smp_processor_id();

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dvit();
    
    if (argc > 1) {
        if (!strcmp(argv[1], "all")) 
            cpu = -1;
        else if (!kdb_str2deci(argv[1], &cpu)) {
            kdbp("Invalid cpu:%d\n", cpu);
            return kdb_usgf_dvit();
        }
    } else
        cpu = ccpu;

    kdbp("(vector in IDT[256] : vector_irq[vector]) (all decimals):\n");
    if (cpu != -1) 
        kdb_prnt_vec_irq_table(cpu);
    else
        for_each_online_cpu(cpu) 
            kdb_prnt_vec_irq_table(cpu);

    kdbp("\nDirect APIC vectors:\n");
    for ( vec = FIRST_DYNAMIC_VECTOR; vec < NR_VECTORS; vec++ )
        if ( direct_apic_vector[vec] )
            printk("   %3d -> %ps()\n", vec, direct_apic_vector[vec]);

    return KDB_CPU_MAIN_KDB;
}

/* do vmexit on all cpu's so intel VMCS can be dumped */
static kdb_cpu_cmd_t kdb_all_cpu_flush_vmcs(void)
{
    int cpu, ccpu = smp_processor_id();
    for_each_online_cpu(cpu) {
        if (cpu == ccpu) {
            kdb_curr_cpu_flush_vmcs();
        } else {
            if (kdb_cpu_cmd[cpu] != KDB_CPU_PAUSE){  /* hung cpu */
                kdbp("Skipping (hung?) cpu %d\n", cpu);
                continue;
            }
            kdb_cpu_cmd[cpu] = KDB_CPU_DO_VMEXIT;
            while (kdb_cpu_cmd[cpu]==KDB_CPU_DO_VMEXIT);
        }
    }
    return KDB_CPU_MAIN_KDB;
}

/* Display VMCS or VMCB */
static kdb_cpu_cmd_t
kdb_usgf_dvmc(void)
{
    kdbp("dvmc [domid][vcpuid] : Dump vmcs/vmcb\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_dvmc(int argc, const char **argv, struct cpu_user_regs *regs)
{
    domid_t domid = 0;  /* unsigned type don't like -1 */
    int vcpuid = -1;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dvmc();

    if (argc > 1) { 
        if (!kdb_str2domid(argv[1], &domid, 1))
            return KDB_CPU_MAIN_KDB;
    }
    if (argc > 2 && !kdb_str2deci(argv[2], &vcpuid)) {
        kdbp("Bad vcpuid: 0x%x\n", vcpuid);
        return KDB_CPU_MAIN_KDB;
    }
    if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
        kdb_all_cpu_flush_vmcs();
        kdb_dump_vmcs(domid, (int)vcpuid);
    } else {
        kdb_dump_vmcb(domid, (int)vcpuid);
    }
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t kdb_usgf_mmio(void)
{
    kdbp("mmio: dump mmio related info\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_mmio(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_mmio();

    kdbp("r/o mmio ranges:\n");
    rangeset_printk(mmio_ro_ranges);
    kdbp("\n");
    return KDB_CPU_MAIN_KDB;
}

/* Dump timer/timers queues */
static kdb_cpu_cmd_t kdb_usgf_dtrq(void)
{
    kdbp("dtrq: dump timer queues on all cpus\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_dtrq(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dtrq();

    kdb_dump_timer_queues();
    return KDB_CPU_MAIN_KDB;
}

struct idte {
    uint16_t offs0_15;
    uint16_t selector;
    uint16_t meta;
    uint16_t offs16_31;
    uint32_t offs32_63;
    uint32_t resvd;
};

#ifdef __x86_64__
static void kdb_print_idte(int num, struct idte *idtp) 
{
    uint16_t mta = idtp->meta;
    char dpl = ((mta & 0x6000) >> 13);
    char present = ((mta &0x8000) >> 15);
    int tval = ((mta &0x300) >> 8);
    char *type = (tval == 1) ? "Task" : ((tval== 2) ? "Intr" : "Trap");
    domid_t domid = idtp->selector==__HYPERVISOR_CS64 ? DOMID_IDLE :
                    current->domain->domain_id;
    uint64_t addr = idtp->offs0_15 | ((uint64_t)idtp->offs16_31 << 16) | 
                    ((uint64_t)idtp->offs32_63 << 32);

    kdbp("[%03d]: %s %x  %x %04x:%016lx ", num, type, dpl, present,
         idtp->selector, addr); 
    kdb_prnt_addr2sym(domid, addr, "");
    kdbp("%s\n", (tval == 2 ? "  (do_IRQ)" : ""));
}

/* Dump 64bit idt table currently on this cpu. Intel Vol 3 section 5.14.1 */
static kdb_cpu_cmd_t
kdb_usgf_didt(void)
{
    kdbp("didt : dump IDT table on the current cpu\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_didt(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int i;
    struct idte *idtp = (struct idte *)idt_tables[smp_processor_id()];

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_didt();

    kdbp("IDT at:%p\n", idtp);
    kdbp("idt#  Type DPL P addr (all hex except idt#)\n", idtp);
    for (i=0; i < 256; i++, idtp++) 
        kdb_print_idte(i, idtp);
    return KDB_CPU_MAIN_KDB;
}
#else
static kdb_cpu_cmd_t
kdb_cmdf_didt(int argc, const char **argv, struct cpu_user_regs *regs)
{
    kdbp("kdb: Please implement me in 32bit hypervisor\n");
    return KDB_CPU_MAIN_KDB;
}
#endif

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

/* Display GDT table. IA-32e mode is assumed. */
/* first display non system descriptors then display system descriptors */
static kdb_cpu_cmd_t
kdb_usgf_dgdt(void)
{
    kdbp("dgdt [gdt-ptr decimal-byte-size [domid]] dump GDT table on current "
         "cpu or for given vcpu\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_dgdt(int argc, const char **argv, struct cpu_user_regs *regs)
{
    struct Xgt_desc_struct desc;
    union gdte_u u1;
    ulong start_addr, end_addr, taddr=0;
    domid_t domid = DOMID_IDLE;
    int idx;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_dgdt();

    if (argc > 1) {
        if (argc == 4 && !kdb_str2domid(argv[3], &domid, 1))
            return kdb_usgf_dgdt();
        if (argc != 3 && argc != 4)
            return kdb_usgf_dgdt();

        if (kdb_str2ulong(argv[1], (ulong *)&start_addr) && 
            kdb_str2deci(argv[2], (int *)&taddr)) {
            end_addr = start_addr + taddr;
        } else {
            kdbp("dgdt: Bad arg:%s or %s\n", argv[1], argv[2]);
            return kdb_usgf_dgdt();
        }
    } else {
        __asm__ __volatile__ ("sgdt  (%0) \n" :: "a"(&desc) : "memory");
        start_addr = (ulong)desc.address; 
        end_addr = (ulong)desc.address + desc.size;
    }
    kdbp("GDT: Will skip null desc at 0, start:%lx end:%lx\n", start_addr, 
         end_addr);
    kdbp("[idx]   sel --- val --------  Accs DPL P AVL L DB G "
         "--Base Addr ----  Limit\n");
    kdbp("                              Type\n");

    /* skip first 8 null bytes */
    /* the cpu multiplies the index by 8 and adds to GDT.base */
    for (taddr = start_addr+8; taddr < end_addr;  taddr += sizeof(ulong)) {

        /* not all entries are mapped. do this to avoid GP even if hyp */
        if (!kdb_read_mem(taddr, (kdbbyt_t *)&u1, sizeof(u1),domid) || !u1.gval)
            continue;

        if (u1.gval == 0xffffffffffffffff || u1.gval == 0x5555555555555555)
            continue;               /* what an effin x86 mess */

        idx = (taddr - start_addr) / 8;
        if (u1.gdte.S == 0) {       /* System Desc are 16 bytes in 64bit mode */
            taddr += sizeof(ulong);
            continue;
        }
        kdbp("[%04x] %04x %016lx  %4s  %x  %d  %d  %d  %d %d %016lx  %05x\n",
             idx, (idx<<3), u1.gval, kdb_ret_acctype(u1.gdte.acctype), 
             u1.gdte.DPL, 
             u1.gdte.P, u1.gdte.AVL, u1.gdte.L, u1.gdte.DB, u1.gdte.G,  
             (u64)((u64)u1.gdte.base0 | (u64)((u64)u1.gdte.base1<<24)), 
             u1.gdte.limit0 | (u1.gdte.limit1<<16));
    }

    kdbp("\nSystem descriptors (S=0) : (skipping 0th entry)\n");
    for (taddr=start_addr+8;  taddr < end_addr;  taddr += sizeof(ulong)) {
        uint acctype;
        u64 upper, addr64=0;

        /* not all entries are mapped. do this to avoid GP even if hyp */
        if (kdb_read_mem(taddr, (kdbbyt_t *)&u1, sizeof(u1), domid)==0 || 
            u1.gval == 0 || u1.gdte.S == 1) {
            continue;
        }
        idx = (taddr - start_addr) / 8;
        taddr += sizeof(ulong);
        if (kdb_read_mem(taddr, (kdbbyt_t *)&upper, 8, domid) == 0) {
            kdbp("Could not read upper 8 bytes of system desc\n");
            upper = 0;
        }
        acctype = u1.gdte.acctype;
        if (acctype != 2 && acctype != 9 && acctype != 11 && acctype !=12 &&
            acctype != 14 && acctype != 15)
            continue;

        kdbp("[%04x] %04x val:%016lx DPL:%x P:%d type:%x ",
             idx, (idx<<3), u1.gval, u1.gdte.DPL, u1.gdte.P, acctype); 

        upper = (u64)((u64)(upper & 0xFFFFFFFF) << 32);

        /* Vol 3A: table: 3-2  page: 3-19 */
        if (acctype == 2) {
            kdbp("LDT gate (0010)\n");
        }
        else if (acctype == 9) {
            kdbp("TSS avail gate(1001)\n");
        }
        else if (acctype == 11) {
            kdbp("TSS busy gate(1011)\n");
        }
        else if (acctype == 12) {
            kdbp("CALL gate (1100)\n");
        }
        else if (acctype == 14) {
            kdbp("IDT gate (1110)\n");
        }
        else if (acctype == 15) {
            kdbp("Trap gate (1111)\n"); 
        }

        if (acctype == 2 || acctype == 9 || acctype == 11) {
            kdbp("        AVL:%d G:%d Base Addr:%016lx Limit:%x\n",
                 u1.gdte.AVL, u1.gdte.G,  
                 (u64)((u64)u1.gdte.base0 | ((u64)u1.gdte.base1<<24)| upper),
                 (u32)u1.gdte.limit0 | (u32)((u32)u1.gdte.limit1<<16));

        } else if (acctype == 12) {
            union sgdte_u u2;
            u2.sgval = u1.gval;

            addr64 = (u64)((u64)u2.cgdte.offs0 | 
                           (u64)((u64)u2.cgdte.offs1<<16) | upper);
            kdbp("        Entry: %04x:%016lx\n", u2.cgdte.sel, addr64);
        } else if (acctype == 14 || acctype == 15) {
            union sgdte_u u2;
            u2.sgval = u1.gval;

            addr64 = (u64)((u64)u2.igdte.offs0 | 
                           (u64)((u64)u2.igdte.offs1<<16) | upper);
            kdbp("        Entry: %04x:%016lx ist:%03x\n", u2.igdte.sel, addr64,
                 u2.igdte.ist);
        } else 
            kdbp(" Error: Unrecongized type:%lx\n", acctype);
    }
    return KDB_CPU_MAIN_KDB;
}

/* Display scheduler basic and extended info */
static kdb_cpu_cmd_t
kdb_usgf_sched(void)
{
    kdbp("sched: show schedular info and run queues\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_sched(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_sched();

    kdb_print_sched_info();
    return KDB_CPU_MAIN_KDB;
}

/* Display MMU basic and extended info */
static kdb_cpu_cmd_t
kdb_usgf_mmu(void)
{
    kdbp("mmu: print basic MMU info\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_mmu(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int cpu;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_mmu();

    kdbp("MMU Info:\n");
    kdbp("total  pages: %lx\n", total_pages);
    kdbp("max page/mfn: %lx\n", max_page);
    kdbp("total_free_pages(): %lx\n", total_free_pages());
    kdbp("frame_table:  %p\n", frame_table);
    kdbp("DIRECTMAP_VIRT_START:  %lx\n", DIRECTMAP_VIRT_START);
    kdbp("DIRECTMAP_VIRT_END:    %lx\n", DIRECTMAP_VIRT_END);
    kdbp("DIRECTMAP_SIZE:   %lx\n", DIRECTMAP_SIZE);
    kdbp("HYPERVISOR_VIRT_START: %lx\n", HYPERVISOR_VIRT_START);
    kdbp("HYPERVISOR_VIRT_END:   %lx\n", HYPERVISOR_VIRT_END);
    kdbp("RO_MPT_VIRT_START:     %lx\n", RO_MPT_VIRT_START);
    kdbp("PERDOMAIN_VIRT_START:  %lx\n", PERDOMAIN_VIRT_START);
    kdbp("CONFIG_PAGING_LEVELS:%d\n", CONFIG_PAGING_LEVELS);
    kdbp("__HYPERVISOR_COMPAT_VIRT_START: %lx\n", 
         (ulong)__HYPERVISOR_COMPAT_VIRT_START);
    kdbp("&MPT[0] == %016lx\n", &machine_to_phys_mapping[0]);

    kdbp("\nFIRST_RESERVED_GDT_PAGE: %x\n", FIRST_RESERVED_GDT_PAGE);
    kdbp("FIRST_RESERVED_GDT_ENTRY: %lx\n", (ulong)FIRST_RESERVED_GDT_ENTRY);
    kdbp("LAST_RESERVED_GDT_ENTRY: %lx\n", (ulong)LAST_RESERVED_GDT_ENTRY);
    kdbp("  Per cpu non-compat gdt_table:\n");
    for_each_online_cpu(cpu) {
        kdbp("\tcpu:%d  gdt_table:%p\n", cpu, per_cpu(gdt_table, cpu));
    }
    kdbp("  Per cpu compat gdt_table:\n");
    for_each_online_cpu(cpu) {
        kdbp("\tcpu:%d  gdt_table:%p\n", cpu, per_cpu(compat_gdt_table, cpu));
    }
    kdbp("\n");
    kdbp("  Per cpu tss:\n");
    for_each_online_cpu(cpu) {
        struct tss_struct *tssp = &per_cpu(init_tss, cpu);
        kdbp("\tcpu:%d  tss:%p (rsp0:%016lx)\n", cpu, tssp, tssp->rsp0);
    }
#ifdef USER_MAPPINGS_ARE_GLOBAL
    kdbp("USER_MAPPINGS_ARE_GLOBAL is defined\n");
#else
    kdbp("USER_MAPPINGS_ARE_GLOBAL is NOT defined\n");
#endif
    kdbp("\n");
    return KDB_CPU_MAIN_KDB;
}

/* for HVM/PVH guests, go thru EPT. For PV guest we need to go to the btree. 
 * btree: pfn_to_mfn_frame_list_list is root that points (has mfns of) upto 16
 * pages (call 'em l2 nodes) that contain mfns of guest p2m table pages 
 * NOTE: num of entries in a p2m page is same as num of entries in l2 node */
static noinline ulong
kdb_gpfn2mfn(struct domain *dp, ulong gpfn, p2m_type_t *typep) 
{
    int idx;

    if ( !paging_mode_translate(dp) ) {
        unsigned long *mfn_va, mfn = arch_get_pfn_to_mfn_frame_list_list(dp);
        int g_longsz = kdb_guest_bitness(dp->domain_id)/8;
        int entries_per_pg = PAGE_SIZE/g_longsz;
        const int shift = get_count_order(entries_per_pg);

	if ( !mfn_valid(mfn) ) {
	    kdbp("Invalid frame_list_list mfn:%lx for non-xlate guest\n", mfn);
	    return INVALID_MFN;
	}

        mfn_va = map_domain_page(mfn);
        idx = gpfn >> 2*shift;     /* index in root page/node */
        if (idx > 15) {
            kdbp("gpfn:%lx idx:%x not in frame list limit of z16\n", gpfn, idx);
            unmap_domain_page(mfn_va);
            return INVALID_MFN;
        }
        mfn = (g_longsz == 4) ? ((int *)mfn_va)[idx] : mfn_va[idx];
        if (mfn==0) {
            kdbp("No mfn for idx:%d for gpfn:%lx in root pg\n", idx, gpfn);
            unmap_domain_page(mfn_va);
            return INVALID_MFN;
        }
        mfn_va = map_domain_page(mfn);
        KDBGP1("p2m: idx:%x fll:%lx mfn of 2nd lvl page:%lx\n", idx,
               arch_get_pfn_to_mfn_frame_list_list(dp), mfn);

        idx = (gpfn>>shift) & ((1<<shift)-1);     /* idx in l2 node */
        mfn = (g_longsz == 4) ? ((int *)mfn_va)[idx] : mfn_va[idx];
        unmap_domain_page(mfn_va);
        if (mfn == 0) {
            kdbp("No mfn entry at:%x in 2nd lvl pg for gpfn:%lx\n", idx, gpfn);
            return INVALID_MFN;
        }
        KDBGP1("p2m: idx:%x  mfn of p2m page:%lx\n", idx, mfn); 
        mfn_va = map_domain_page(mfn);
        idx = gpfn & ((1<<shift)-1);
        mfn = (g_longsz == 4) ? ((int *)mfn_va)[idx] : mfn_va[idx];
        unmap_domain_page(mfn_va);

	*typep = -1;
        return mfn;
    } else
        return mfn_x(get_gfn_query_unlocked(dp, gpfn, typep));

    return INVALID_MFN;
}

/* given a pfn, find it's mfn */
static kdb_cpu_cmd_t
kdb_usgf_p2m(void)
{
    kdbp("p2m domid 0xgpfn : gpfn to mfn\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_p2m(int argc, const char **argv, struct cpu_user_regs *regs)
{
    struct domain *dp;
    ulong gpfn, mfn=0xdeadbeef;
    p2m_type_t p2mtype = -1;

    if (argc < 3                                   ||
        (dp=kdb_strdomid2ptr(argv[1], 1)) == NULL  ||
        !kdb_str2ulong(argv[2], &gpfn)) {

        return kdb_usgf_p2m();
    }
    mfn = kdb_gpfn2mfn(dp, gpfn, &p2mtype);
    if ( paging_mode_translate(dp) )
        kdbp("p2m[%lx] == %lx type:%d/0x%x\n", gpfn, mfn, p2mtype, p2mtype);
    else 
        kdbp("p2m[%lx] == %lx type:N/A(PV)\n", gpfn, mfn);

    return KDB_CPU_MAIN_KDB;
}

/* given an mfn, lookup pfn in the MPT */
static kdb_cpu_cmd_t
kdb_usgf_m2p(void)
{
    kdbp("m2p 0xmfn: mfn to pfn\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_m2p(int argc, const char **argv, struct cpu_user_regs *regs)
{
    unsigned long mfn;
    if (argc > 1 && kdb_str2ulong(argv[1], &mfn))
        if (mfn_valid(mfn))
            kdbp("mpt[%x] == %lx\n", mfn, machine_to_phys_mapping[mfn]);
        else
            kdbp("Invalid mfn:%lx\n", mfn);
    else
        kdb_usgf_m2p();
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_iommu(void)
{
    kdbp("dump iommu p2m table for all domains\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_iommu(int argc, const char **argv, struct cpu_user_regs *regs)
{
    struct domain *d;
    const struct iommu_ops *ops;
        
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_iommu();

    if ( !iommu_enabled )
    {
        kdbp("IOMMU not enabled!\n");
        return KDB_CPU_MAIN_KDB;
    }

    ops = iommu_get_ops();
    for_each_domain(d)
    {
        struct hvm_iommu *hd  = domain_hvm_iommu(d);

        if ( is_pv_domain(d) ) 
        {
            kdbp("Skip PV domain:%d\n", d->domain_id);
            continue;
        }
        if ( iommu_use_hap_pt(d) )
        {
            kdbp("domain iommu uses hap pt.\n", d->domain_id);
            continue;
        }
    
#if XEN_VERSION == 4 && XEN_SUBVERSION < 5 
        kdbp("Domain:%d hvm_iommu:%p\n", d->domain_id, hd);
        kdbp("    pgd_maddr:%p paging_mode:%d root_table:%p\n",
             hd->pgd_maddr, hd->paging_mode, hd->root_table);
#else
        kdbp("Domain:%d arch_hvm_iommu:%p\n", d->domain_id, &hd->arch);
        kdbp("    pgd_maddr:%p paging_mode:%d root_table:%p\n",
             hd->arch.pgd_maddr, hd->arch.paging_mode, hd->arch.root_table);
        kdbp("Dumping domain IOMMU p2m table:\n", d->domain_id);
        ops->dump_p2m_table(d);
#endif
    }
    return KDB_CPU_MAIN_KDB;
}

static void 
kdb_pr_pg_pgt_flds(unsigned long type_info)
{
    switch (type_info & PGT_type_mask) {
        case (PGT_l1_page_table):
            kdbp("    page is PGT_l1_page_table\n");
            break;
        case PGT_l2_page_table:
            kdbp("    page is PGT_l2_page_table\n");
            break;
        case PGT_l3_page_table:
            kdbp("    page is PGT_l3_page_table\n");
            break;
        case PGT_l4_page_table:
            kdbp("    page is PGT_l4_page_table\n");
            break;
        case PGT_seg_desc_page:
            kdbp("    page is seg desc page\n");
            break;
        case PGT_writable_page:
            kdbp("    page is writable page\n");
            break;
        case PGT_shared_page:
            kdbp("    page is shared page\n");
            break;
    }
    if (type_info & PGT_pinned)
        kdbp("    page is pinned\n");
    if (type_info & PGT_validated)
        kdbp("    page is validated\n");
    if (type_info & PGT_pae_xen_l2)
        kdbp("    page is PGT_pae_xen_l2\n");
    if (type_info & PGT_partial)
        kdbp("    page is PGT_partial\n");
    if (type_info & PGT_locked)
        kdbp("    page is PGT_locked\n");
}

static void
kdb_pr_pg_pgc_flds(unsigned long count_info)
{
    if (count_info & PGC_allocated)
        kdbp("  PGC_allocated");
    if (count_info & PGC_xen_heap)
        kdbp("  PGC_xen_heap");
    if (count_info & PGC_page_table)
        kdbp("  PGC_page_table");
    if (count_info & PGC_broken)
        kdbp("  PGC_broken");
#if XEN_VERSION < 4                                 /* xen 3.x.x */
    if (count_info & PGC_offlining)
        kdbp("  PGC_offlining");
    if (count_info & PGC_offlined)
        kdbp("  PGC_offlined");
#else
    if (count_info & PGC_state_inuse)
        kdbp("  PGC_inuse");
    if (count_info & PGC_state_offlining)
        kdbp("  PGC_state_offlining");
    if (count_info & PGC_state_offlined)
        kdbp("  PGC_state_offlined");
    if (count_info & PGC_state_free)
        kdbp("  PGC_state_free");
#endif
    kdbp("\n");
}

/* print struct page_info{} given ptr to it or an mfn
 * NOTE: that given an mfn there seems no way of knowing how it's used, so
 *       here we just print all info and let user decide what's applicable */
static kdb_cpu_cmd_t
kdb_usgf_dpage(void)
{
    kdbp("dpage mfn|page-ptr : Display struct page\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_dpage(int argc, const char **argv, struct cpu_user_regs *regs)
{
    unsigned long val;
    struct page_info *pgp;
    struct domain *dp;

    if (argc <= 1 || *argv[1] == '?') 
        return kdb_usgf_dpage();

    if ((kdb_str2ulong(argv[1], &val) == 0)      ||
        (val <  (ulong)frame_table && !mfn_valid(val))) {

        kdbp("Invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    kdbp("Page Info:\n");
    if (val <= (ulong)frame_table) {       /* arg is mfn */
        pgp = mfn_to_page(val);
        kdbp("  mfn: %lx page_info:%p\n", val, pgp);
    } else {
        pgp = (struct page_info *)val; /* arg is struct page{} */
        if (pgp < frame_table || pgp >= frame_table+max_page) {
            kdbp("Invalid page ptr. below/beyond max_page\n");
            return KDB_CPU_MAIN_KDB;
        }
        kdbp("  mfn: %lx page_info:%p\n", page_to_mfn(pgp), pgp);
    } 
    kdbp("  count_info: %016lx  (refcnt: %x)\n", pgp->count_info,
         pgp->count_info & PGC_count_mask);
#if XEN_VERSION > 3 || XEN_SUBVERSION > 3             /* xen 3.4.x or later */
    kdb_pr_pg_pgc_flds(pgp->count_info);

    kdbp("In use info:\n");
    kdbp("  type_info:%016lx\n", pgp->u.inuse.type_info);
    kdb_pr_pg_pgt_flds(pgp->u.inuse.type_info);
    dp = page_get_owner(pgp);
    kdbp("  domid:%d (pickled:%lx)\n", dp ? dp->domain_id : -1, 
         pgp->v.inuse._domain);

    kdbp("Shadow Info:\n");
    kdbp("  type:%x pinned:%x count:%x\n", pgp->u.sh.type, pgp->u.sh.pinned,
         pgp->u.sh.count);
    kdbp("  back:%lx  shadow_flags:%x  next_shadow:%lx\n", pgp->v.sh.back,
         pgp->shadow_flags, pgp->next_shadow);

    kdbp("Free Info\n");
    kdbp("  need_tlbflush:%d order:%d tlbflush_timestamp:%x\n",
         pgp->u.free.need_tlbflush, pgp->v.free.order, 
         pgp->tlbflush_timestamp);
#else
    if (pgp->count_info & PGC_allocated)            /* page allocated */
        kdbp("  PGC_allocated");
    if (pgp->count_info & PGC_page_table)           /* page table page */
        kdbp("  PGC_page_table");
    kdbp("\n");
    kdbp("  page is %s xen heap page\n", is_xen_heap_page(pgp) ? "a":"NOT");
    kdbp("  cacheattr:%x\n", (pgp->count_info>>PGC_cacheattr_base) & 7);
    if (pgp->count_info & PGC_count_mask) {         /* page in use */
        dp = pgp->u.inuse._domain;         /* pickled domain */
        kdbp("  page is in use\n");
        kdbp("    domid: %d  (pickled dom:%x)\n", 
             dp ? (unpickle_domptr(dp))->domain_id : -1, dp);
        kdbp("    type_info: %lx\n", pgp->u.inuse.type_info);
        kdb_prt_pg_type(pgp->u.inuse.type_info);
    } else {                                         /* page is free */
        kdbp("  page is free\n");
        kdbp("    order: %x\n", pgp->u.free.order);
        kdbp("    cpumask: %lx\n", pgp->u.free.cpumask.bits);
    }
    kdbp("  tlbflush/shadow_flags: %lx\n", pgp->shadow_flags);
#endif
    return KDB_CPU_MAIN_KDB;
}

/* display asked msr value */
static kdb_cpu_cmd_t
kdb_usgf_dmsr(void)
{
    kdbp("dmsr address : Display msr value\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_dmsr(int argc, const char **argv, struct cpu_user_regs *regs)
{
    unsigned long addr, val;

    if (argc <= 1 || *argv[1] == '?') 
        return kdb_usgf_dmsr();

    if ((kdb_str2ulong(argv[1], &addr) == 0)) {
        kdbp("Invalid arg:%s\n", argv[1]);
        return KDB_CPU_MAIN_KDB;
    }
    rdmsrl(addr, val);
    kdbp("msr: %lx  val:%lx\n", addr, val);

    return KDB_CPU_MAIN_KDB;
}

/* execute cpuid for given value */
static kdb_cpu_cmd_t
kdb_usgf_cpuid(void)
{
    kdbp("cpuid eax : Display cpuid value returned in rax\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_cpuid(int argc, const char **argv, struct cpu_user_regs *regs)
{
    unsigned long rax=0, rbx=0, rcx=0, rdx=0;

    if (argc <= 1 || *argv[1] == '?') 
        return kdb_usgf_cpuid();

    if ((kdb_str2ulong(argv[1], &rax) == 0)) {
        kdbp("Invalid arg:%s\n", argv[1]);
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
    cpuid(rax, &rax, &rbx, &rcx, &rdx);
    kdbp("rax: %016lx  rbx:%016lx rcx:%016lx rdx:%016lx\n", rax, rbx,
         rcx, rdx);
    return KDB_CPU_MAIN_KDB;
}

/* execute cpuid for given value */
static kdb_cpu_cmd_t
kdb_usgf_wept(void)
{
    kdbp("wept domid gfn: walk ept table for given domid and gfn\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_wept(int argc, const char **argv, struct cpu_user_regs *regs)
{
    struct domain *dp;
    ulong gfn;

    if ((argc > 1 && *argv[1] == '?') || argc != 3)
        return kdb_usgf_wept();
    if ((dp=kdb_strdomid2ptr(argv[1], 1)) && kdb_str2ulong(argv[2], &gfn))
        ept_walk_table(dp, gfn);
    else
        kdb_usgf_wept();

    return KDB_CPU_MAIN_KDB;
}

/*
 * Save symbols info for a guest, dom0 or other...
 */
static kdb_cpu_cmd_t
kdb_usgf_sym(void)
{
   kdbp("sym domid &kallsyms_names &kallsyms_addresses &kallsyms_num_syms\n");
   kdbp("\t [&kallsyms_token_table] [&kallsyms_token_index]\n");
   kdbp("\ttoken _table and _index MUST be specified for el5\n");
   return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_sym(int argc, const char **argv, struct cpu_user_regs *regs)
{
    ulong namesp, addrap, nump, toktblp, tokidxp;
    domid_t domid;

    if (argc < 5) {
        return kdb_usgf_sym();
    }
    toktblp = tokidxp = 0;     /* optional parameters */
    if (kdb_str2domid(argv[1], &domid, 1) &&
        kdb_str2ulong(argv[2], &namesp)   &&
        kdb_str2ulong(argv[3], &addrap)   &&
        kdb_str2ulong(argv[4], &nump)     && 
        (argc==5 || (argc==7 && kdb_str2ulong(argv[5], &toktblp) &&
                                kdb_str2ulong(argv[6], &tokidxp)))) {

        kdb_sav_dom_syminfo(domid, namesp, addrap,nump,toktblp,tokidxp);
    } else
        kdb_usgf_sym();
    return KDB_CPU_MAIN_KDB;
}


/* mods is the dumb ass &modules. modules is struct {nxt, prev}, and not ptr */
static void
kdb_dump_linux_modules(domid_t domid, ulong mods, uint nxtoffs, uint nmoffs, 
                       uint coreoffs)
{
    const int bufsz = 56;
    char buf[bufsz];
    uint64_t addr, addrval, *nxtptr, *modptr;
    uint i, num = 8;

    if (kdb_guest_bitness(domid) == 32)
        num = 4;

    /* first read modules{}.next ptr */
    if (kdb_read_mem(mods, (kdbbyt_t *)&nxtptr, num, domid) != num) {
        kdbp("ERROR: Could not read next at mod:%p\n", (void *)mods);
        return;
    }

    KDBGP("mods:%p nxtptr:%p nmoffs:%x coreoffs:%x\n", (void *)mods, nxtptr,
          nmoffs, coreoffs);

    while ((uint64_t)nxtptr != mods) {

        modptr = (uint64_t *) ((ulong)nxtptr - nxtoffs);

        addr = (ulong)modptr + coreoffs;
        if (kdb_read_mem(addr, (kdbbyt_t *)&addrval, num, domid) != num) {
            kdbp("ERROR: Could not read mod addr at :%p\n", (void *)addr);
            return;
        }

        KDBGP("modptr:%p addr:%p\n", modptr, (void *)addr);
        addr = (ulong)modptr + nmoffs;
        i=0;
        do {
            if (kdb_read_mem(addr, (kdbbyt_t *)&buf[i], 1, domid) != 1) {
                kdbp("ERROR:Could not read name ch at addr:%p\n", (void *)addr);
                return;
            }
            addr++;
        } while (buf[i] && i++ < bufsz);
        buf[bufsz-1] = '\0';

        kdbp("%016lx %016lx %s\n", modptr, addrval, buf);

        if (kdb_read_mem((ulong)nxtptr, (kdbbyt_t *)&nxtptr, num, domid)!=num) {
            kdbp("ERROR: Could not read next at mod:%p\n", (void *)mods);
            return;
        }
        KDBGP("nxtptr:%p addr:%p\n", nxtptr, (void *)addr);
    } 
}

/* Display modules loaded in linux guest */
static kdb_cpu_cmd_t
kdb_usgf_mod(void)
{
   kdbp("mod domid &modules next-offs name-offs module_core-offs\n");
   kdbp("\twhere next-offs: &((struct module *)0)->list.next\n");
   kdbp("\tname-offs: &((struct module *)0)->name etc..\n");
   kdbp("\tDisplays all loaded modules in the linux guest\n");
   kdbp("\tEg: mod 0 ffffffff80302780 8 0x18 0x178\n");

   return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_cmdf_mod(int argc, const char **argv, struct cpu_user_regs *regs)
{
    ulong mods, nxtoffs, nmoffs, coreoffs;
    domid_t domid;

    if (argc < 6) {
        return kdb_usgf_mod();
    }
    if (kdb_str2domid(argv[1], &domid, 1) &&
        kdb_str2ulong(argv[2], &mods)     &&
        kdb_str2ulong(argv[3], &nxtoffs)  &&
        kdb_str2ulong(argv[4], &nmoffs)   &&
        kdb_str2ulong(argv[5], &coreoffs)) {

        kdbp("modptr address name\n");
        kdb_dump_linux_modules(domid, mods, nxtoffs, nmoffs, coreoffs);
    } else
        kdb_usgf_mod();
    return KDB_CPU_MAIN_KDB;
}

/* toggle kdb debug trace level */
static kdb_cpu_cmd_t
kdb_usgf_kdbdbg(void)
{
    kdbp("kdbdbg : trace info to debug kdb\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_kdbdbg(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_kdbdbg();

    kdbdbg = (kdbdbg==3) ? 0 : (kdbdbg+1);
    kdbp("kdbdbg set to:%d\n", kdbdbg);
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_reboot(void)
{
    kdbp("reboot: reboot system\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_reboot(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_reboot();

    machine_restart(500);
    return KDB_CPU_MAIN_KDB;              /* not reached */
}


static kdb_cpu_cmd_t kdb_usgf_clrstat(void)
{
    kdbp("clrstat: clear all stats\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_clrstat(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_clrstat();

    kdb_clear_stats();
    return KDB_CPU_MAIN_KDB;
}


static kdb_cpu_cmd_t kdb_usgf_trcon(void)
{
    kdbp("trcon: turn user added kdb tracing on\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_trcon(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_trcon();

    kdb_trcon = 1;
    kdbp("kdb tracing is now on\n");
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_trcoff(void)
{
    kdbp("trcoff: turn user added kdb tracing off\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_trcoff(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_trcoff();

    kdb_trcon = 0;
    kdbp("kdb tracing is now off\n");
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_trcz(void)
{
    kdbp("trcz : zero entire trace buffer\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_trcz(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_trcz();

    kdb_trczero();
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_trcp(void)
{
    kdbp("trcp : give hints to dump trace buffer via dw/dd command\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_trcp(int argc, const char **argv, struct cpu_user_regs *regs)
{
    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_trcp();

    kdb_trcp();
    return KDB_CPU_MAIN_KDB;
}

/* print some basic info, constants, etc.. */
static kdb_cpu_cmd_t
kdb_usgf_info(void)
{
    kdbp("info : display basic info, constants, etc..\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_info(int argc, const char **argv, struct cpu_user_regs *regs)
{
    int cpu;
    struct domain *dp;
    struct cpuinfo_x86 *bcdp;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_info();

    kdbp("Version: %d.%d.%s (%s@%s) %s\n", xen_major_version(), 
         xen_minor_version(), xen_extra_version(), xen_compile_by(), 
         xen_compile_domain(), xen_compile_date());
    kdbp("__XEN_LATEST_INTERFACE_VERSION__ : 0x%x\n", 
         __XEN_LATEST_INTERFACE_VERSION__);
    kdbp("__XEN_INTERFACE_VERSION__: 0x%x\n", __XEN_INTERFACE_VERSION__);

    bcdp = &boot_cpu_data;
    kdbp("CPU: (all decimal)");
        if (bcdp->x86_vendor == X86_VENDOR_AMD)
            kdbp(" AMD");
        else
            kdbp(" INTEL");
        kdbp(" family:%d model:%d\n", bcdp->x86, bcdp->x86_model);
        kdbp("     vendor_id:%16s model_id:%64s\n", bcdp->x86_vendor_id,
             bcdp->x86_model_id);
        kdbp("     cpuidlvl:%d cache:sz:%d align:%d\n", bcdp->cpuid_level,
             bcdp->x86_cache_size, bcdp->x86_cache_alignment);
        kdbp("     power:%d cores: max:%d booted:%d siblings:%d apicid:%d\n",
             bcdp->x86_power, bcdp->x86_max_cores, bcdp->booted_cores,
             bcdp->x86_num_siblings, bcdp->apicid);
        kdbp("     ");
        if (cpu_has_apic)
            kdbp("_apic");
        if (cpu_has_sep)
            kdbp("|_sep");
        if (cpu_has_xmm3)
            kdbp("|_xmm3");
        if (cpu_has_ht)
            kdbp("|_ht");
        if (cpu_has_nx)
            kdbp("|_nx");
        if (cpu_has_clflush)
            kdbp("|_clflush");
        if (cpu_has_page1gb)
            kdbp("|_page1gb");
        if (cpu_has_ffxsr)
            kdbp("|_ffxsr");
        if (cpu_has_x2apic)
            kdbp("|_x2apic");
    kdbp("\n\n");
    kdbp("CC:");
#if defined(CONFIG_X86_64)
        kdbp(" CONFIG_X86_64");
#endif
#if defined(CONFIG_COMPAT)
        kdbp(" CONFIG_COMPAT");
#endif
#if defined(CONFIG_PAGING_ASSISTANCE)
        kdbp(" CONFIG_PAGING_ASSISTANCE");
#endif
    kdbp("\n");
    kdbp("cpu has following features:\n");
    kdbp("  %s\n", boot_cpu_has(X86_FEATURE_TSC_RELIABLE) ? 
         "X86_FEATURE_TSC_RELIABLE" : "");
    kdbp("  %s\n", 
         boot_cpu_has(X86_FEATURE_CONSTANT_TSC)? "X86_FEATURE_CONSTANT_TSC":"");
    kdbp("  %s\n", 
         boot_cpu_has(X86_FEATURE_NONSTOP_TSC) ? "X86_FEATURE_NONSTOP_TSC" :"");
    kdbp("  %s\n", 
         boot_cpu_has(X86_FEATURE_RDTSCP) ?  "X86_FEATURE_RDTSCP" : "");
    kdbp("  %s\n", boot_cpu_has(X86_FEATURE_FXSR) ?  "X86_FEATURE_FXSR" : "");
    kdbp("  %s\n", boot_cpu_has(X86_FEATURE_CPUID_FAULTING) ?  
         "X86_FEATURE_CPUID_FAULTING" : "");
    kdbp("  %s\n", 
         boot_cpu_has(X86_FEATURE_PAGE1GB) ?  "X86_FEATURE_PAGE1GB" : "");
    kdbp("  %s\n", boot_cpu_has(X86_FEATURE_MWAIT) ?  "X86_FEATURE_MWAIT" : "");
    kdbp("  %s\n", boot_cpu_has(X86_FEATURE_X2APIC) ?  "X86_FEATURE_X2APIC":"");
    kdbp("  %s\n", boot_cpu_has(X86_FEATURE_XSAVE) ?  "X86_FEATURE_XSAVE":"");
    kdbp("\n");

    kdbp("NR_CPUS:$%d MAX_VIRT_CPUS:$%d  MAX_HVM_VCPUS:$%d\n", 
         NR_CPUS, MAX_VIRT_CPUS,MAX_HVM_VCPUS);

    kdbp("cpu#  apicid(dec/hex)\n");
    for_each_online_cpu(cpu) {
        __u32 apicid = cpu_data[cpu].apicid;
        kdbp("[%3d]  %d/%x\n", cpu, apicid, apicid);
    }
    kdbp("\n");

#if XEN_VERSION >= 4 && XEN_SUBVERSION > 1       /* 4.2.x or later */ 
    kdbp("MAX_NR_EVTCHNS: $%d\n", MAX_NR_EVTCHNS);
    kdbp("NR_EVTCHN_GROUPS: $%d\n", NR_EVTCHN_GROUPS);
#else
    kdbp("NR_EVENT_CHANNELS: $%d\n", NR_EVENT_CHANNELS);
    kdbp("NR_EVTCHN_BUCKETS: $%d\n", NR_EVTCHN_BUCKETS);
#endif

    kdbp("\nDomains and their vcpus:\n");
    for_each_domain(dp) {
        struct vcpu *vp;
        int printed=0;
        kdbp("  Domain: {id:%d 0x%x   ptr:%p%s}  VCPUs:\n", 
             dp->domain_id, dp->domain_id, dp, dp->is_dying ? " DYING":"");
        for(vp=dp->vcpu[0]; vp; vp = vp->next_in_list) {
            kdbp("  {id:%d p:%p runstate:%d}", vp->vcpu_id, vp, 
                 vp->runstate.state);
            if (++printed % 2 == 0) kdbp("\n");
        }
        kdbp("\n");
    }
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_cur(void)
{
    kdbp("cur : display current domid and vcpu\n");
    return KDB_CPU_MAIN_KDB;
}

/* Checking for guest_mode() not feasible here. if dom0->hcall->bp in xen, 
 * then g_m() will show xen, but vcpu is still dom0. hence just look at 
 * current only */
static kdb_cpu_cmd_t
kdb_cmdf_cur(int argc, const char **argv, struct cpu_user_regs *regs)
{
    domid_t id = current->domain->domain_id;

    if (argc > 1 && *argv[1] == '?')
        return kdb_usgf_cur();

    kdbp("domid: %d{%p} %s vcpu:%d {%p} ", id, current->domain,
         (id==DOMID_IDLE) ? "(IDLE)" : "", current->vcpu_id, current);

    /* if (id != DOMID_IDLE) { */
        if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
            u64 addr = -1;
            __vmptrst(&addr);
            kdbp(" VMCS:"KDBFL, addr);
        }
    /* } */
    kdbp("\n");
    return KDB_CPU_MAIN_KDB;
}

/* stub to quickly and easily add a new command */
static kdb_cpu_cmd_t
kdb_usgf_usr1(void)
{
    kdbp("usr1: add any arbitrary cmd using this in kdb_cmds.c\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_usr1(int argc, const char **argv, struct cpu_user_regs *regs)
{
    return KDB_CPU_MAIN_KDB;
}

static kdb_cpu_cmd_t
kdb_usgf_h(void)
{
    kdbp("h: display all commands. See kdb/README for more info\n");
    return KDB_CPU_MAIN_KDB;
}
static kdb_cpu_cmd_t
kdb_cmdf_h(int argc, const char **argv, struct cpu_user_regs *regs)
{
    kdbtab_t *tbp;

    kdbp(" - ccpu is current cpu \n");
    kdbp(" - following are always in decimal:\n");
    kdbp("     vcpu num, cpu num, domid\n");
    kdbp(" - otherwise, almost all numbers are in hex (0x not needed)\n");
    kdbp(" - output: $17 means decimal 17\n");
    kdbp(" - domid 7fff($32767) refers to hypervisor\n");
    kdbp(" - if no domid before function name, then it's hypervisor\n");
    kdbp(" - earlykdb in xen grub line to break into kdb during boot\n");
    kdbp(" - command ? will show the command usage\n");
    kdbp("\n");

    for(tbp=kdb_cmd_tbl; tbp->kdb_cmd_usgf; tbp++)
        (*tbp->kdb_cmd_usgf)();
    return KDB_CPU_MAIN_KDB;
}

/* ===================== cmd table initialization ========================== */
void __init
kdb_init_cmdtab(void)
{
  static kdbtab_t _kdb_cmd_table[] = {

    {"info", kdb_cmdf_info, kdb_usgf_info, 1, KDB_REPEAT_NONE},
    {"cur",  kdb_cmdf_cur, kdb_usgf_cur, 1, KDB_REPEAT_NONE},

    {"f",  kdb_cmdf_f,  kdb_usgf_f,  1, KDB_REPEAT_NONE},
    {"fg", kdb_cmdf_fg, kdb_usgf_fg, 1, KDB_REPEAT_NONE},

    {"dw",  kdb_cmdf_dw,  kdb_usgf_dw,  1, KDB_REPEAT_NO_ARGS},
    {"dd",  kdb_cmdf_dd,  kdb_usgf_dd,  1, KDB_REPEAT_NO_ARGS},
    {"dwm", kdb_cmdf_dwm, kdb_usgf_dwm, 1, KDB_REPEAT_NO_ARGS},
    {"ddm", kdb_cmdf_ddm, kdb_usgf_ddm, 1, KDB_REPEAT_NO_ARGS},
    {"dr",  kdb_cmdf_dr,  kdb_usgf_dr,  1, KDB_REPEAT_NONE},
    {"drg", kdb_cmdf_drg, kdb_usgf_drg, 1, KDB_REPEAT_NONE},

    {"dis", kdb_cmdf_dis,  kdb_usgf_dis,  1, KDB_REPEAT_NO_ARGS},
    {"dism",kdb_cmdf_dism, kdb_usgf_dism, 1, KDB_REPEAT_NO_ARGS},

    {"mw", kdb_cmdf_mw, kdb_usgf_mw, 1, KDB_REPEAT_NONE},
    {"md", kdb_cmdf_md, kdb_usgf_md, 1, KDB_REPEAT_NONE},
    {"mr", kdb_cmdf_mr, kdb_usgf_mr, 1, KDB_REPEAT_NONE},

    {"bc", kdb_cmdf_bc, kdb_usgf_bc, 0, KDB_REPEAT_NONE},
    {"bp", kdb_cmdf_bp, kdb_usgf_bp, 1, KDB_REPEAT_NONE},
    {"btp", kdb_cmdf_btp, kdb_usgf_btp, 1, KDB_REPEAT_NONE},

    {"wp", kdb_cmdf_wp, kdb_usgf_wp, 1, KDB_REPEAT_NONE},
    {"wc", kdb_cmdf_wc, kdb_usgf_wc, 0, KDB_REPEAT_NONE},

    {"ni", kdb_cmdf_ni, kdb_usgf_ni, 0, KDB_REPEAT_NO_ARGS},
    {"ss", kdb_cmdf_ss, kdb_usgf_ss, 1, KDB_REPEAT_NO_ARGS},
    {"ssb",kdb_cmdf_ssb,kdb_usgf_ssb,0, KDB_REPEAT_NO_ARGS},
    {"go", kdb_cmdf_go, kdb_usgf_go, 0, KDB_REPEAT_NONE},

    {"cpu",kdb_cmdf_cpu, kdb_usgf_cpu, 1, KDB_REPEAT_NONE},
    {"nmi",kdb_cmdf_nmi, kdb_usgf_nmi, 1, KDB_REPEAT_NONE},
    {"percpu",kdb_cmdf_percpu, kdb_usgf_percpu, 1, KDB_REPEAT_NONE},

    {"sym",  kdb_cmdf_sym,   kdb_usgf_sym,   1, KDB_REPEAT_NONE},
    {"mod",  kdb_cmdf_mod,   kdb_usgf_mod,   1, KDB_REPEAT_NONE},

    {"vcpuh",kdb_cmdf_vcpuh, kdb_usgf_vcpuh, 1, KDB_REPEAT_NONE},
    {"vcpu", kdb_cmdf_vcpu,  kdb_usgf_vcpu,  1, KDB_REPEAT_NONE},
    {"dom",  kdb_cmdf_dom,   kdb_usgf_dom,   1, KDB_REPEAT_NONE},

    {"sched", kdb_cmdf_sched, kdb_usgf_sched, 1, KDB_REPEAT_NONE},
    {"mmu",   kdb_cmdf_mmu,   kdb_usgf_mmu,   1, KDB_REPEAT_NONE},
    {"p2m",   kdb_cmdf_p2m,   kdb_usgf_p2m,   1, KDB_REPEAT_NONE},
    {"iommu", kdb_cmdf_iommu,   kdb_usgf_iommu,   1, KDB_REPEAT_NONE},
    {"m2p",   kdb_cmdf_m2p,   kdb_usgf_m2p,   1, KDB_REPEAT_NONE},
    {"dpage", kdb_cmdf_dpage, kdb_usgf_dpage, 1, KDB_REPEAT_NONE},
    {"dmsr",  kdb_cmdf_dmsr,  kdb_usgf_dmsr, 1, KDB_REPEAT_NONE},
    {"cpuid",  kdb_cmdf_cpuid,  kdb_usgf_cpuid, 1, KDB_REPEAT_NONE},
    {"wept",  kdb_cmdf_wept,  kdb_usgf_wept, 1, KDB_REPEAT_NONE},

    {"dtrq", kdb_cmdf_dtrq,  kdb_usgf_dtrq, 1, KDB_REPEAT_NONE},
    {"didt", kdb_cmdf_didt,  kdb_usgf_didt, 1, KDB_REPEAT_NONE},
    {"dgdt", kdb_cmdf_dgdt,  kdb_usgf_dgdt, 1, KDB_REPEAT_NONE},
    {"dirq", kdb_cmdf_dirq,  kdb_usgf_dirq, 1, KDB_REPEAT_NONE},
    {"dvit", kdb_cmdf_dvit,  kdb_usgf_dvit, 1, KDB_REPEAT_NONE},
    {"dvmc", kdb_cmdf_dvmc,  kdb_usgf_dvmc, 1, KDB_REPEAT_NONE},
    {"mmio", kdb_cmdf_mmio,  kdb_usgf_mmio, 1, KDB_REPEAT_NONE},

    /* perf/stat related commands */
    {"clrstat", kdb_cmdf_clrstat,  kdb_usgf_clrstat,  0, KDB_REPEAT_NONE},

    /* tracing related commands */
    {"trcon", kdb_cmdf_trcon,  kdb_usgf_trcon,  0, KDB_REPEAT_NONE},
    {"trcoff",kdb_cmdf_trcoff, kdb_usgf_trcoff, 0, KDB_REPEAT_NONE},
    {"trcz",  kdb_cmdf_trcz,   kdb_usgf_trcz,   0, KDB_REPEAT_NONE},
    {"trcp",  kdb_cmdf_trcp,   kdb_usgf_trcp,   1, KDB_REPEAT_NONE},

    {"usr1",  kdb_cmdf_usr1,   kdb_usgf_usr1,   1, KDB_REPEAT_NONE},
    {"kdbf",  kdb_cmdf_kdbf,   kdb_usgf_kdbf,   1, KDB_REPEAT_NONE},
    {"kdbdbg",kdb_cmdf_kdbdbg, kdb_usgf_kdbdbg, 1, KDB_REPEAT_NONE},
    {"reboot",kdb_cmdf_reboot, kdb_usgf_reboot, 1, KDB_REPEAT_NONE},
    {"h",     kdb_cmdf_h,      kdb_usgf_h,      1, KDB_REPEAT_NONE},

    {"", NULL, NULL, 0, 0},
  };
    kdb_cmd_tbl = _kdb_cmd_table;
    return;
}
