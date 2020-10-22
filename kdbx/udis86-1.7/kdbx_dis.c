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

#include "../include/kdbxinc.h"
#include "extern.h"

static void (*dis_syntax)(ud_t*) = UD_SYN_ATT; /* default dis-assembly syntax */

static struct {                         /* info for kdb_read_byte_for_ud() */
    kdbva_t kud_instr_addr;
    pid_t kud_gpid;
} kdb_ud_rd_info;

/* called via function ptr by ud when disassembling. 
 * kdb info passed via kdb_ud_rd_info{} 
 */
static int kdb_read_byte_for_ud(struct ud *udp)
{
    kdbbyt_t bytebuf;
    kdbva_t addr = kdb_ud_rd_info.kud_instr_addr;
    pid_t gpid = kdb_ud_rd_info.kud_gpid;
    struct kvm_vcpu *vp = kdbx_pid_to_vcpu(gpid, 0);

    if (kdbx_read_mem(addr, &bytebuf, 1, vp) == 1) {
        kdb_ud_rd_info.kud_instr_addr++;
        KDBGP1("udrd:addr:%lx gpid:%d byte:%x\n", addr, gpid, bytebuf);
        return bytebuf;
    }
    KDBGP1("udrd:addr:%lx gpid:%d err\n", addr, gpid);
    return UD_EOI;
}

/* convert addr to symbol and return in buf
 * if gpid == -1, just return addr in buf
 * NOTE: buf size must be KSYM_NAME_LEN+16 (for guestpid prefix) 
 */
char *kdbx_addr2sym(pid_t gpid, kdbva_t addr, char *buf, int needoffs)
{
    unsigned long sz, offs, symfound = 0;
    char prefix[8], *p = buf;

    prefix[0] = '\0';     /* guest pid */
    // snprintf(buf, KSYM_NAME_LEN+16, " (null) ");

    if ( gpid != -1 && addr ) {
        if ( gpid ) {
            snprintf(prefix, 8, "%d:", gpid);
            p = kdbx_guest_addr2sym(addr, gpid, &offs);
            if ( p )
                symfound = 1;
        } else {
            kallsyms_lookup(addr, &sz, &offs, NULL, buf);
            if ( *buf )
                symfound = 1;
        }
    }
    if ( symfound ) {
        if ( needoffs )
            snprintf(buf, KSYM_NAME_LEN+16, "%s%s+%lx", prefix, p, offs);
        else
            snprintf(buf, KSYM_NAME_LEN+16, "%s%s", prefix, p);
    } else {
        if ( addr )
            snprintf(buf, KSYM_NAME_LEN+16, " %s%016lx ", prefix, addr);
        else
            buf[0] = '\0';
    }
    return buf;
}

/* 
 * convert addr to symbol and print it 
 * Eg: ffff828c801235e2: idle_loop+52                  jmp  idle_loop+55
 *    Called twice here for idle_loop. In first case, nl is null, 
 *    in the second case nl == '\n'
 */
void kdbx_prnt_addr2sym(pid_t gpid, kdbva_t addr, char *nl)
{
    char buf[KSYM_NAME_LEN+16]; 

    kdbx_addr2sym(gpid, addr, buf, 1);

    if (*nl != '\n')
        kdbxp("%-28s%s", buf, nl);  /* prints more than 30 if needed */
    else
        kdbxp("%s%s", buf, nl);
}

static int kdb_jump_instr(enum ud_mnemonic_code mnemonic)
{
    return (mnemonic >= UD_Ijo && mnemonic <= UD_Ijmp);
}

/*
 * print one instr: function so that we can print offsets of jmp etc.. as
 *  symbol+offset instead of just address
 */
static void kdb_print_one_instr(struct ud *udp, pid_t gpid)
{
    signed long val = 0;
    ud_type_t type = udp->operand[0].type;

    if ((udp->mnemonic == UD_Icall || kdb_jump_instr(udp->mnemonic)) &&
        type == UD_OP_JIMM) {
        
        int sz = udp->operand[0].size;
        char *p, ibuf[40], *q = ibuf;
        kdbva_t addr;

        if (sz == 8) val = udp->operand[0].lval.sbyte;
        else if (sz == 16) val = udp->operand[0].lval.sword;
        else if (sz == 32) val = udp->operand[0].lval.sdword;
        else if (sz == 64) val = udp->operand[0].lval.sqword;
        else kdbxp("kdb_print_one_instr: Inval sz:z%d\n", sz);

        addr = udp->pc + val;
        for(p=ud_insn_asm(udp); (*q=*p) && *p!=' '; p++,q++);
        *q='\0';
        kdbxp(" %-4s ", ibuf);    /* space before for long func names */
        kdbx_prnt_addr2sym(gpid, addr, "\n");
    } else
        kdbxp(" %-24s\n", ud_insn_asm(udp));
#if 0
    kdbxp("mnemonic:z%d ", udp->mnemonic);
    if (type == UD_OP_CONST) kdbxp("type is const\n");
    else if (type == UD_OP_JIMM) kdbxp("type is JIMM\n");
    else if (type == UD_OP_IMM) kdbxp("type is IMM\n");
    else if (type == UD_OP_PTR) kdbxp("type is PTR\n");
#endif
}

static void kdb_setup_ud(struct ud *udp, kdbva_t addr, pid_t gpid)
{
    uint vendor = (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) ?
                                           UD_VENDOR_AMD : UD_VENDOR_INTEL;

    KDBGP1("setup_ud:addr:%lx gpid:%d\n", addr, gpid);
    ud_init(udp);
    ud_set_mode(udp, gpid ? kdbx_guest_bitness(gpid) : 64);/* host always 64 */
    ud_set_syntax(udp, dis_syntax); 
    ud_set_vendor(udp, vendor);           /* HVM: vmx/svm different instrs*/
    ud_set_pc(udp, addr);                 /* for numbers printed on left */
    ud_set_input_hook(udp, kdb_read_byte_for_ud);
    kdb_ud_rd_info.kud_instr_addr = addr;
    kdb_ud_rd_info.kud_gpid = gpid;
}

/*
 * given an addr, print given number of instructions.
 * Returns: address of next instruction in the stream
 */
kdbva_t kdbx_print_instr(kdbva_t addr, long num, pid_t gpid)
{
    struct ud ud_s;

    KDBGP1("print_instr:addr:0x%lx num:%ld gpid:%d\n", addr, num, gpid);

    kdb_setup_ud(&ud_s, addr, gpid);
    while(num--) {
        if (ud_disassemble(&ud_s)) {
            uint64_t pc = ud_insn_off(&ud_s);

            kdbxp("%016lx: ", pc);
            kdbx_prnt_addr2sym(gpid, pc, "");
            kdb_print_one_instr(&ud_s, gpid);
        } else
            kdbxp("KDB:Couldn't disassemble PC:0x%lx\n", addr);
            /* for stack reads, don't always display error */
    }
    KDBGP1("print_instr:kudaddr:0x%lx\n", kdb_ud_rd_info.kud_instr_addr);

    return kdb_ud_rd_info.kud_instr_addr;
}

/* check if the instr at the addr is call instruction
 * RETURNS: size of the instr if it's a call instr, else 0
 */
int kdbx_check_call_instr(kdbva_t addr, pid_t gpid)
{
    struct ud ud_s;
    int sz;

    kdb_setup_ud(&ud_s, addr, gpid);
    if ((sz=ud_disassemble(&ud_s)) && ud_s.mnemonic == UD_Icall)
        return (sz);

    return 0;
}

/* toggle ATT and Intel syntaxes */
void kdbx_toggle_dis_syntax(void)
{
    if (dis_syntax == UD_SYN_INTEL) {
        dis_syntax = UD_SYN_ATT;
        kdbxp("dis syntax now set to ATT (Gas)\n");
    } else {
        dis_syntax = UD_SYN_INTEL;
        kdbxp("dis syntax now set to Intel (NASM)\n");
    }
}
