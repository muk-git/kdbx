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

#ifndef _KDBDEFS_H
#define _KDBDEFS_H

typedef unsigned long kdbva_t;
typedef unsigned char kdbbyt_t;
typedef unsigned long kdbma_t;

/* reason we are entering kdbmain (bp == breakpoint) */
typedef enum {
    KDB_REASON_KEYBOARD=1,  /* Keyboard entry - always 1 */
    KDB_REASON_DBEXCP,      /* #DB excp: TF flag or HW bp */
    KDB_REASON_BPEXCP,      /* #BP excp: sw bp (INT3) */
    KDB_REASON_PAUSE_IPI,   /* received pause IPI from another CPU */
} kdb_reason_t;


/* cpu state: past, present, and future */
typedef enum {
    KDB_CPU_INVAL,       /*  0: invalid value. not in or leaving kdb */
    KDB_CPU_QUIT,        /*  1: main cpu does GO. all others do QUIT */
    KDB_CPU_PAUSE,       /*  2: cpu is paused */
#if 0
    KDB_CPU_DISABLE,     /*  3: disable interrupts */
#endif
    KDB_CPU_SHOWPC,      /*  4: all cpus must display their pc */
    KDB_CPU_DO_VMEXIT,   /*  5: all cpus must do vmcs vmexit. intel only */
    KDB_CPU_MAIN_KDB,    /*  6: cpu in kdb main command loop */
    KDB_CPU_GO,          /*  7: user entered go for this cpu */
    KDB_CPU_SS,          /*  8: single step for this cpu */
    KDB_CPU_NI,          /*  9: go to next instr after the call instr */
    KDB_CPU_INSTALL_BP,  /* 10: delayed install of sw bp(s) by this cpu */
} kdb_cpu_cmd_t;

/* ============= kdb commands ============================================= */

typedef kdb_cpu_cmd_t (*kdb_func_t)(int, const char **, struct pt_regs *);
typedef kdb_cpu_cmd_t (*kdb_usgf_t)(void);

typedef enum {
    KDB_REPEAT_NONE = 0,    /* Do not repeat this command */
    KDB_REPEAT_NO_ARGS,     /* Repeat the command without arguments */
    KDB_REPEAT_WITH_ARGS,   /* Repeat the command including its arguments */
} kdb_repeat_t;

typedef struct _kdbtab {
    char        *kdb_cmd_name;        /* Command name */
    kdb_func_t   kdb_cmd_func;        /* ptr to function to execute command */
    kdb_usgf_t   kdb_cmd_usgf;        /* usage function ptr */
    int          kdb_cmd_crash_avail; /* available in sys fatal/crash state */
    kdb_repeat_t kdb_cmd_repeat;      /* Does command auto repeat on enter? */
} kdbtab_t;


/* ============= types and stuff ========================================= */
#define BFD_INVAL (~0UL)            /* invalid bfd_vma */

#if defined(__x86_64__)
  #define KDBIP ip
  #define KDBSP sp
#else
  #define KDBIP eip
  #define KDBSP esp
#endif

/* ============= macros ================================================== */
extern volatile int kdbdbg;
#define KDBGP(...) {(kdbdbg) ? kdbxp(__VA_ARGS__):0;}
#define KDBGP1(...) {(kdbdbg>1) ? kdbxp(__VA_ARGS__):0;}
#define KDBGP2(...) {(kdbdbg>2) ? kdbxp(__VA_ARGS__):0;}
#define KDBGP3(...) {0;};

#define KDBMIN(x,y) (((x)<(y))?(x):(y))

#define ASSERT(x) {                                                     \
    if (!(x)) {                                                         \
        kdbxp("ASSERT %s FAILED: %s:%d\n", #x, __func__, __LINE__);      \
    }                                                                   \
}

#define irqs_enabled() (!irqs_disabled())

#endif  /* !_KDBDEFS_H */
