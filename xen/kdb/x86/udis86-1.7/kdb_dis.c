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

#include <xen/compile.h>                /* for XEN_SUBVERSION */
#include "../../include/kdbinc.h"
#include "extern.h"

static void (*dis_syntax)(ud_t*) = UD_SYN_ATT; /* default dis-assembly syntax */

static struct {                         /* info for kdb_read_byte_for_ud() */
    kdbva_t kud_instr_addr;
    domid_t kud_domid;
} kdb_ud_rd_info;

/* called via function ptr by ud when disassembling. 
 * kdb info passed via kdb_ud_rd_info{} 
 */
static int
kdb_read_byte_for_ud(struct ud *udp)
{
    kdbbyt_t bytebuf;
    domid_t domid = kdb_ud_rd_info.kud_domid;
    kdbva_t addr = kdb_ud_rd_info.kud_instr_addr;

    if (kdb_read_mem(addr, &bytebuf, 1, domid) == 1) {
        kdb_ud_rd_info.kud_instr_addr++;
        KDBGP1("udrd:addr:%lx domid:%d byt:%x\n", addr, domid, bytebuf);
        return bytebuf;
    }
    KDBGP1("udrd:addr:%lx domid:%d err\n", addr, domid);
    return UD_EOI;
}

/* 
 * given a domid, convert addr to symbol and print it 
 * Eg: ffff828c801235e2: idle_loop+52                  jmp  idle_loop+55
 *    Called twice here for idle_loop. In first case, nl is null, 
 *    in the second case nl == '\n'
 */
void
kdb_prnt_addr2sym(domid_t domid, kdbva_t addr, char *nl)
{
    unsigned long sz, offs;
    char buf[KSYM_NAME_LEN+1], pbuf[150], prefix[8];
    char *p = buf;

    prefix[0]='\0';
    if (domid != DOMID_IDLE) {
        snprintf(prefix, 8, "%x:", domid);
        p = kdb_guest_addr2sym(addr, domid, &offs);
    } else
        symbols_lookup(addr, &sz, &offs, buf);

    snprintf(pbuf, 150, "%s%s+%lx", prefix, p, offs);
    if (*nl != '\n')
        kdbp("%-30s%s", pbuf, nl);  /* prints more than 30 if needed */
    else
        kdbp("%s%s", pbuf, nl);

}

static int
kdb_jump_instr(enum ud_mnemonic_code mnemonic)
{
    return (mnemonic >= UD_Ijo && mnemonic <= UD_Ijmp);
}

/*
 * print one instr: function so that we can print offsets of jmp etc.. as
 *  symbol+offset instead of just address
 */
static void
kdb_print_one_instr(struct ud *udp, domid_t domid)
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
        else kdbp("kdb_print_one_instr: Inval sz:z%d\n", sz);

        addr = udp->pc + val;
        for(p=ud_insn_asm(udp); (*q=*p) && *p!=' '; p++,q++);
        *q='\0';
        kdbp(" %-4s ", ibuf);    /* space before for long func names */
        kdb_prnt_addr2sym(domid, addr, "\n");
    } else
        kdbp(" %-24s\n", ud_insn_asm(udp));
#if 0
    kdbp("mnemonic:z%d ", udp->mnemonic);
    if (type == UD_OP_CONST) kdbp("type is const\n");
    else if (type == UD_OP_JIMM) kdbp("type is JIMM\n");
    else if (type == UD_OP_IMM) kdbp("type is IMM\n");
    else if (type == UD_OP_PTR) kdbp("type is PTR\n");
#endif
}

static void
kdb_setup_ud(struct ud *udp, kdbva_t addr, domid_t domid)
{
    int bitness = kdb_guest_bitness(domid);
    uint vendor = (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) ?
                                           UD_VENDOR_AMD : UD_VENDOR_INTEL;

    KDBGP1("setup_ud:domid:%d bitness:%d addr:%lx\n", domid, bitness, addr);
    ud_init(udp);
    ud_set_mode(udp, kdb_guest_bitness(domid));
    ud_set_syntax(udp, dis_syntax); 
    ud_set_vendor(udp, vendor);           /* HVM: vmx/svm different instrs*/
    ud_set_pc(udp, addr);                 /* for numbers printed on left */
    ud_set_input_hook(udp, kdb_read_byte_for_ud);
    kdb_ud_rd_info.kud_instr_addr = addr;
    kdb_ud_rd_info.kud_domid = domid;
}

/*
 * given an addr, print given number of instructions.
 * Returns: address of next instruction in the stream
 */
kdbva_t
kdb_print_instr(kdbva_t addr, long num, domid_t domid)
{
    struct ud ud_s;

    KDBGP1("print_instr:addr:0x%lx num:%ld domid:%x\n", addr, num, domid);

    kdb_setup_ud(&ud_s, addr, domid);
    while(num--) {
        if (ud_disassemble(&ud_s)) {
            uint64_t pc = ud_insn_off(&ud_s);
            /* kdbp("%08x: ",(int)pc); */
            kdbp("%016lx: ", pc);
            kdb_prnt_addr2sym(domid, pc, "");
            kdb_print_one_instr(&ud_s, domid);
        } else
            kdbp("KDB:Couldn't disassemble PC:0x%lx\n", addr);
            /* for stack reads, don't always display error */
    }
    KDBGP1("print_instr:kudaddr:0x%lx\n", kdb_ud_rd_info.kud_instr_addr);
    return kdb_ud_rd_info.kud_instr_addr;
}

void
kdb_display_pc(struct cpu_user_regs *regs)
{   
    domid_t domid;
    struct cpu_user_regs regs1 = *regs;
    domid = guest_mode(regs) ? current->domain->domain_id : DOMID_IDLE;

    regs1.KDBIP = regs->KDBIP;
    kdb_print_instr(regs1.KDBIP, 1, domid);
}

/* check if the instr at the addr is call instruction
 * RETURNS: size of the instr if it's a call instr, else 0
 */
int
kdb_check_call_instr(domid_t domid, kdbva_t addr)
{
    struct ud ud_s;
    int sz;

    kdb_setup_ud(&ud_s, addr, domid);
    if ((sz=ud_disassemble(&ud_s)) && ud_s.mnemonic == UD_Icall)
        return (sz);
    return 0;
}

/* toggle ATT and Intel syntaxes */
void
kdb_toggle_dis_syntax(void)
{
    if (dis_syntax == UD_SYN_INTEL) {
        dis_syntax = UD_SYN_ATT;
        kdbp("dis syntax now set to ATT (Gas)\n");
    } else {
        dis_syntax = UD_SYN_INTEL;
        kdbp("dis syntax now set to Intel (NASM)\n");
    }
}
