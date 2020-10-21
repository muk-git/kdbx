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
#ifndef _KDB_EXTERN_H
#define _KDB_EXTERN_H

/* This file included from include/xen/lib.h */

#define KDB_TRAP_FATAL     1    /* trap is fatal. can't resume from kdb */
#define KDB_TRAP_NONFATAL  2    /* can resume from kdb */
#define KDB_TRAP_KDBSTACK  3    /* to debug kdb itself. dump kdb stack */

/* following can be called from anywhere in xen to debug */
extern void kdb_trap_immed(int);
extern void kdbtrc(unsigned int, unsigned int, uint64_t, uint64_t, uint64_t);
extern void kdbp(const char *fmt, ...);
extern int kdb_fetch_and_add(int i, uint *p);
extern void kdb_update_stats(uint, uint, ulong, ulong);

typedef unsigned long kdbva_t;
typedef unsigned char kdbbyt_t;
typedef unsigned long kdbma_t;

extern unsigned long kdb_dr7;

extern volatile int kdb_session_begun;
extern volatile int kdb_enabled;
extern void kdb_init(void);
extern int kdb_keyboard(struct cpu_user_regs *);
extern void kdb_ssni_reenter(struct cpu_user_regs *);
extern int kdb_handle_trap_entry(int, const struct cpu_user_regs *);
extern int kdb_trap_fatal(int, struct cpu_user_regs *);  /* fatal with regs */
extern void kdb_dump_vmcs(uint16_t did, int vid);
void kdb_dump_vmcb(uint16_t did, int vid);
extern void kdb_dump_time_pcpu(void);


#define VMPTRST_OPCODE  ".byte 0x0f,0xc7\n"     /* reg/opcode: /7 */
#define MODRM_EAX_07    ".byte 0x38\n"          /* [EAX], with reg/opcode: /7 */
static inline void __vmptrst(u64 *addr)
{
    asm volatile ( VMPTRST_OPCODE
                   MODRM_EAX_07
                   :
                   : "a" (addr)
                   : "memory");
}

extern void mukchk(unsigned long);

#endif  /* _KDB_EXTERN_H */
