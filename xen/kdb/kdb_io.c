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

#define K_BACKSPACE  0x8                   /* ctrl-H */
#define K_BACKSPACE1 0x7f                  /* ctrl-? */
#define K_UNDERSCORE 0x5f
#define K_CMD_BUFSZ  160
#define K_CMD_MAXI   (K_CMD_BUFSZ - 1)     /* max index in buffer */

#if 0        /* make a history array some day */
#define K_UP_ARROW                         /* sequence : 1b 5b 41 ie, '\e[A' */
#define K_DN_ARROW                         /* sequence : 1b 5b 42 ie, '\e[B' */
#define K_NUM_HIST   32
static int cursor;
static char cmds_a[NUM_HIST][K_CMD_BUFSZ];
#endif

static char cmds_a[K_CMD_BUFSZ];


static int
kdb_key_valid(int key)
{
    /* note: isspace() is more than ' ', hence we don't use it here */
    if (isalnum(key) || key == ' ' || key == K_BACKSPACE || key == '\n' ||
        key == '?' || key == K_UNDERSCORE || key == '=' || key == '!')
            return 1;
    return 0;
}

/* display kdb prompt and read command from the console 
 * RETURNS: a '\n' terminated command buffer */
char *
kdb_get_cmdline(char *prompt)
{
    #define K_BELL     0x7
    #define K_CTRL_C   0x3

    int key, i=0;

    kdbp(prompt);
    memset(cmds_a, 0, K_CMD_BUFSZ);
    cmds_a[K_CMD_BUFSZ-1] = '\n';

    do {
        key = console_getc();
        if (key == '\r') 
            key = '\n';
        if (key == K_BACKSPACE1) 
            key = K_BACKSPACE;

        if (key == K_CTRL_C || (i==K_CMD_MAXI && key != '\n')) {
            console_putc('\n');
            if (i >= K_CMD_MAXI) {
                kdbp("KDB: cmd buffer overflow\n");
                console_putc(K_BELL);
            }
            memset(cmds_a, 0, K_CMD_BUFSZ);
            i = 0;
            kdbp(prompt);
            continue;
        }
        if (!kdb_key_valid(key)) {
            console_putc(K_BELL);
            continue;
        }
        if (key == K_BACKSPACE) {
            if (i==0) {
                console_putc(K_BELL);
                continue;
            } else {
                cmds_a[--i] = '\0';
                console_putc(K_BACKSPACE);
                console_putc(' ');        /* erase character */
            }
        } else
            cmds_a[i++] = key;

        console_putc(key);

    } while (key != '\n');

    return cmds_a;
}

/*
 * printk takes a lock, an NMI could come in after that, and another cpu may 
 * spin. also, the console lock is forced unlock, so panic is been seen on 
 * 8 way. hence, no printk() calls.
 */
static volatile int kdbp_gate = 0;
void
kdbp(const char *fmt, ...)
{
    static char buf[1024];
    va_list args;
    char *p;
    int i=0;

    while ((__cmpxchg(&kdbp_gate, 0,1, sizeof(kdbp_gate)) != 0) && i++<1000)
        mdelay(10);

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    for (p=buf; *p != '\0'; p++)
        console_putc(*p);
    kdbp_gate = 0;
}


/*
 * copy/read machine memory. 
 * RETURNS: number of bytes copied 
 */
int
kdb_read_mmem(kdbma_t maddr, kdbbyt_t *dbuf, int len)
{
    ulong remain, orig=len;

    while (len > 0) {
        ulong pagecnt = min_t(long, PAGE_SIZE-(maddr&~PAGE_MASK), len);
        char *va = map_domain_page(maddr >> PAGE_SHIFT);

        va = va + (maddr & (PAGE_SIZE-1));        /* add page offset */
        remain = __copy_from_user(dbuf, (void *)va, pagecnt);
        KDBGP1("maddr:%x va:%p len:%x pagecnt:%x rem:%x\n", 
               maddr, va, len, pagecnt, remain);
        unmap_domain_page(va);
        len = len  - (pagecnt - remain);
        if (remain != 0)
            break;
        maddr += pagecnt;
        dbuf += pagecnt;
    }
    return orig - len;
}


/*
 * copy/read guest or hypervisor memory. (domid == DOMID_IDLE) => hyp
 * RETURNS: number of bytes copied 
 */
int
kdb_read_mem(kdbva_t saddr, kdbbyt_t *dbuf, int len, domid_t domid)
{
    return (len - dbg_rw_mem(saddr, dbuf, len, domid, 0, 0));
}

/*
 * write guest or hypervisor memory. (domid == DOMID_IDLE) => hyp
 * RETURNS: number of bytes written
 */
int
kdb_write_mem(kdbva_t daddr, kdbbyt_t *sbuf, int len, domid_t domid)
{
    return (len - dbg_rw_mem(daddr, sbuf, len, domid, 1, 0));
}
