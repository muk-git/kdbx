/*
 * Copyright (C) 2009, 2019 Mukesh Rathor, Oracle Corp.  All rights reserved.
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

#define DR_LOCAL_ENABLE_MASK (0x55)  /* Set  local bits for all 4 regs */
#define DR_GLOBAL_ENABLE_MASK (0xAA) /* Set global bits for all 4 regs */
#define DR7_ACTIVE_MASK (DR_LOCAL_ENABLE_MASK|DR_GLOBAL_ENABLE_MASK)

#if 0
#define DR6_BT  0x00008000
#define DR6_BS  0x00004000
#define DR6_BD  0x00002000
#endif
#define DR6_B3  0x00000008
#define DR6_B2  0x00000004
#define DR6_B1  0x00000002
#define DR6_B0  0x00000001

#define KDB_MAXWP 4                          /* DR0 thru DR3 */

struct kdb_wp {
    kdbma_t  wp_addr;
    int      wp_rwflag;
    int      wp_len;
    int      wp_deleted;                     /* pending delete */
};
static struct kdb_wp kdb_wpa[KDB_MAXWP];

/* WPs are slow... so unless they are being used, just skip all this */
static volatile int kdb_wp_active;

/* following because vmcs has it's own dr7. when vmcs runs, it messes up the
 * native dr7 so we need to save/restore it */
unsigned long kdb_dr7;


/* Set G0-G3 bits in DR7. this does global enable of the corresponding wp */
static void
kdb_set_gx_in_dr7(int regno, kdbma_t *dr7p)
{
    if (regno == 0)
        *dr7p = *dr7p | 0x2;
    else if (regno == 1)
        *dr7p = *dr7p | 0x8;
    else if (regno == 2)
        *dr7p = *dr7p | 0x20;
    else if (regno == 3)
        *dr7p = *dr7p | 0x80;
}

/* Set LEN0 - LEN3 pair bits in DR7 (len should be 1 2 4 or 8) */
static void
kdb_set_len_in_dr7(int regno, kdbma_t *dr7p, int len)
{
    int lenbits = (len == 8) ? 2 : len-1;

    *dr7p &= ~(0x3 << (18 + 4*regno));
    *dr7p |= ((ulong)(lenbits & 0x3) << (18 + 4*regno));
}

static void
kdb_set_dr7_rw(int regno, kdbma_t *dr7p, int rw)
{
    *dr7p &= ~(0x3 << (16 + 4*regno));
    *dr7p |= ((ulong)(rw & 0x3)) << (16 + 4*regno);
}

/* get value of a debug register: DR0-DR3 DR6 DR7. other values return 0 */
kdbma_t kdbx_rd_dbgreg(int regnum)
{
    kdbma_t contents = 0;

    if (regnum == 0)
        __asm__ ("movq %%db0,%0\n\t":"=r"(contents));
    else if (regnum == 1)
        __asm__ ("movq %%db1,%0\n\t":"=r"(contents));
    else if (regnum == 2)
        __asm__ ("movq %%db2,%0\n\t":"=r"(contents));
    else if (regnum == 3)
        __asm__ ("movq %%db3,%0\n\t":"=r"(contents));
    else if (regnum == 6)
        __asm__ ("movq %%db6,%0\n\t":"=r"(contents));
    else if (regnum == 7)
        __asm__ ("movq %%db7,%0\n\t":"=r"(contents));

    return contents;
}

static void
kdb_wr_dbgreg(int regnum, kdbma_t contents)
{
    if (regnum == 0)
        __asm__ ("movq %0,%%db0\n\t"::"r"(contents));
    else if (regnum == 1)
        __asm__ ("movq %0,%%db1\n\t"::"r"(contents));
    else if (regnum == 2)
        __asm__ ("movq %0,%%db2\n\t"::"r"(contents));
    else if (regnum == 3)
        __asm__ ("movq %0,%%db3\n\t"::"r"(contents));
    else if (regnum == 6)
        __asm__ ("movq %0,%%db6\n\t"::"r"(contents));
    else if (regnum == 7)
        __asm__ ("movq %0,%%db7\n\t"::"r"(contents));
}

static void
kdb_print_wp_info(char *strp, int idx)
{
    kdbxp("%s[%d]:%016lx len:%d ", strp, idx, kdb_wpa[idx].wp_addr,
         kdb_wpa[idx].wp_len);
    if (kdb_wpa[idx].wp_rwflag == 1)
        kdbxp("on data write only\n");
    else if (kdb_wpa[idx].wp_rwflag == 2)
        kdbxp("on IO read/write\n");
    else 
        kdbxp("on data read/write\n");
}

/*
 * Returns : 0 if not one of ours
 *           1 if one of ours
 */
int kdbx_check_watchpoints(struct pt_regs *regs)
{
    int wpnum;
    kdbma_t dr6 = kdbx_rd_dbgreg(6);

    KDBGP1("check_wp: IP:%lx EFLAGS:%lx\n", regs->ip, regs->flags);
    if (dr6 & DR6_B0)
        wpnum = 0;
    else if (dr6 & DR6_B1)
        wpnum = 1;
    else if (dr6 & DR6_B2)
        wpnum = 2;
    else if (dr6 & DR6_B3)
        wpnum = 3;
    else
        return 0;

    kdb_print_wp_info("Watchpoint ", wpnum);
    return 1;
}

/* set a watchpoint at a given address 
 * PreCondition: addr != 0 */
static void kdb_set_wp(kdbva_t addr, int rwflag, int len)
{
    int regno;

    for (regno=0; regno < KDB_MAXWP; regno++) {
        if (kdb_wpa[regno].wp_addr == addr && !kdb_wpa[regno].wp_deleted) {
            kdbxp("Watchpoint already set\n");
            return;
        }
        if (kdb_wpa[regno].wp_deleted)
            memset(&kdb_wpa[regno], 0, sizeof(kdb_wpa[regno]));
    }
    for (regno=0; regno < KDB_MAXWP && kdb_wpa[regno].wp_addr; regno++);
    if (regno >= KDB_MAXWP) {
        kdbxp("watchpoint table full. limit:%d\n", KDB_MAXWP);
        return;
    }
    kdb_wpa[regno].wp_addr = addr;
    kdb_wpa[regno].wp_rwflag = rwflag;
    kdb_wpa[regno].wp_len = len;
    kdb_print_wp_info("Watchpoint set ", regno);
    kdb_wp_active = 1;
}

/* write reg DR0-3 with address. Update corresponding bits in DR7 */
static void kdb_install_watchpoint(int regno, kdbma_t *dr7p)
{
    kdb_set_gx_in_dr7(regno, dr7p);
    kdb_set_len_in_dr7(regno, dr7p, kdb_wpa[regno].wp_len); 
    kdb_set_dr7_rw(regno, dr7p, kdb_wpa[regno].wp_rwflag);
    kdb_wr_dbgreg(regno, kdb_wpa[regno].wp_addr);

    KDBGP1("ccpu:%d installed wp. addr:%lx rw:%x len:%x dr7:%016lx\n",
           smp_processor_id(), kdb_wpa[regno].wp_addr, 
           kdb_wpa[regno].wp_rwflag, kdb_wpa[regno].wp_len, *dr7p);
}

/* clear G0-G3 bits in DR7 for given DR0-3 */
static void kdb_clear_dr7_gx(int regno, kdbma_t *dr7p)
{
    if (regno == 0)
        *dr7p = *dr7p & ~0x2;
    else if (regno == 1)
        *dr7p = *dr7p & ~0x8;
    else if (regno == 2)
        *dr7p = *dr7p & ~0x20;
    else if (regno == 3)
        *dr7p = *dr7p & ~0x80;
}

/* update dr7 once, as it's slow to update debug regs and cpu's will still be 
 * paused when leaving kdb.
 *
 * Just leave DR0-3 clobbered but remove bits from DR7 to disable wp 
 */
void kdbx_install_watchpoints(void)
{
    int regno;
    kdbma_t dr7;

    if ( !kdb_wp_active )
        return;

    dr7 = kdbx_rd_dbgreg(7);

    for (regno=0; regno < KDB_MAXWP; regno++) {
        /* do not clear wp_deleted here as all cpus must clear wps */
        if (kdb_wpa[regno].wp_deleted) {
            kdb_clear_dr7_gx(regno, &dr7);
            continue;
        }
        if (kdb_wpa[regno].wp_addr)
            kdb_install_watchpoint(regno, &dr7);
    }
    /* always clear DR6 when leaving */
    kdb_wr_dbgreg(6, 0);
    kdb_wr_dbgreg(7, dr7);

    if (dr7 & DR7_ACTIVE_MASK)
        kdb_dr7 = dr7;
    else
        kdb_dr7 = 0;
#if 0
    for(dp=domain_list; dp; dp=dp->next_in_list) {
        struct vcpu *vp;
        for_each_vcpu(dp, vp) {
            for (regno=0; regno < KDB_MAXWP; regno++)
                vp->arch.guest_context.debugreg[regno] = kdb_wpa[regno].wp_addr;

            vp->arch.guest_context.debugreg[6] = 0;
            vp->arch.guest_context.debugreg[7] = dr7;
            KDBGP("kdb_install_watchpoints(): v:%px dr7:%lx\n", vp, dr7);
            /* hvm_set_info_guest(vp);: Can't because can't vmcs_enter in kdb */
        }
    }
#endif
}

/* clear watchpoint/s. wpnum == -1 to clear all watchpoints */
void kdbx_clear_wps(int wpnum)
{
    int i;

    if (wpnum >= KDB_MAXWP) {
        kdbxp("Invalid wpnum %d\n", wpnum);
        return;
    }
    if (wpnum >=0) {
        if (kdb_wpa[wpnum].wp_addr) {
            kdb_wpa[wpnum].wp_deleted = 1;
            kdb_print_wp_info("Deleted watchpoint", wpnum);
        } else
            kdbxp("watchpoint %d not set\n", wpnum);

        for (i=0; i < KDB_MAXWP && 
                  (kdb_wpa[i].wp_addr == 0 || kdb_wpa[i].wp_deleted); i++);
        if ( i >= KDB_MAXWP )
            kdb_wp_active = 0;

        return;
    }
    for (i=0; i < KDB_MAXWP; i++) {
        if (kdb_wpa[i].wp_addr) {
            kdb_wpa[i].wp_deleted = 1;
            kdb_print_wp_info("Deleted watchpoint", i);
        }
    }
    kdb_wp_active = 0;
}

/* display any watchpoints that are set */
static void kdb_display_wps(void)
{
    int i;
    for (i=0; i < KDB_MAXWP; i++)
        if (kdb_wpa[i].wp_addr && !kdb_wpa[i].wp_deleted) 
            kdb_print_wp_info("", i);
}

/* 
 * Display or Set hardware breakpoints, ie, watchpoints:
 *   - Upto 4 are allowed
 *   
 *  rw_flag should be one of: 
 *     01 == break on data write only
 *     10 == break on IO read/write
 *     11 == Break on data reads or writes
 *
 *  len should be one of : 1 2 4 8 
 */
void kdbx_do_watchpoints(kdbva_t addr, int rw_flag, int len)
{
    if (addr == 0) {
        kdb_display_wps();        /* display set watchpoints */
        return;
    }
    kdb_set_wp(addr, rw_flag, len);
    return;
}

