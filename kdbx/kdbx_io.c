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

extern int console_set_on_cmdline;

static char cmds_a[K_CMD_BUFSZ];

/* ====> old code at the bottom */

static int kdbx_serial_base = 0x3f8;  /* default to ttyS0 */
static int kdbx_default_baud = 115200;  /* default to ttyS0 */
static volatile int kdbxp_gate = 0;

#define XMTRDY          0x20    /* MUK: bit 5 in the LSR */
#define RCVRDY          0x01    /* MUK: bit 0 in the LSR */

#define DLAB		0x80

#define TXR             0       /*  Transmit register (WRITE) */
#define RXR             0       /*  Receive register  (READ)  */
#define IER             1       /*  Interrupt Enable          */
#define IIR             2       /*  Interrupt ID              */
#define FCR             2       /*  FIFO control              */
#define LCR             3       /*  Line control              */
#define MCR             4       /*  Modem control             */
#define LSR             5       /*  Line Status               */
#define MSR             6       /*  Modem Status              */
#define DLL             0       /*  Divisor Latch Low         */
#define DLH             1       /*  Divisor latch High        */

/* copied from kernel/prink.c */
struct console_cmdline
{
        char    name[8];                        /* Name of the driver       */
        int     index;                          /* Minor dev. to use        */
        char    *options;                       /* Options for the driver   */
};


/*
 * TBD: we run in polling mode. IER, interrupt mode, is disabled so in case of
 *      data in, the UART will not interrupt us. When breaking into KDBX, add 
 *      code to disable IER if it's enabled by the tty drivers, then restore it.
 *      Done by serial tty driver.
 */
static void kdbx_init_serial_info(char *cmdline)
{
    char *p = strstr(cmdline, "ttyS");

    if ( p == NULL ) {
        pr_notice(">>> kdbx: console= in cmdline not set.... \n");
        return;
    }

    /* parse : console=ttyS0,115200n8 */
    p += 4;
    if ( *p == '0' )
        kdbx_serial_base = 0x3f8;  /* ttyS0 */
    else if ( *p == '1' )
        kdbx_serial_base = 0x2f8;  /* ttyS1 */
    else {
        pr_notice(">>> kdbx: ttyS%c in cmdline not recognized\n", *p);
        return;
    }
    p++;
    if ( *p == ',' )
        p++;
    else
        return;

    if ( strstr(p, "115200") )
        kdbx_default_baud = 115200;
    else if ( strstr(p, "57600") )
        kdbx_default_baud = 57600;
    else if ( strstr(p, "28800") )
        kdbx_default_baud = 28800;
    else if ( strstr(p, "14400") )
        kdbx_default_baud = 14400;
    else if ( strstr(p, "7200") )
        kdbx_default_baud = 7200;
    else if ( strstr(p, "3600") )
        kdbx_default_baud = 3600;
    else
        pr_notice("kdbx: %s baud not recognized\n", p);

    return;

#if 0
    while ( (ccp = kdbx_get_console_cmdline(idx++)) ) {

        /* console_cmdline: name:ttyS idx:0 opts:115200n8 */
        if ( strcmp(ccp->name, "ttyS") == 0 ) {

            if (ccp->index == 1)
                kdbx_serial_base = 0x2f8;  /* ttyS1 */

            /* will stop at first non-digit */
            baud = simple_strtol(ccp->options, NULL, 10);
            if (baud)
                kdbx_default_baud = baud;

            break;
        }
    }

    extern char *boot_command_line;   /* of size COMMAND_LINE_SIZE */
    char *cp = NULL;
    int baud = 115200;

    /* need to check for space before after the = sign */
    if ( (cp = strstr("console=ttyS0", boot_command_line)) )
        kdbx_serial_base = 0x3f8;
    else if ( (cp = strstr("console=ttyS1", boot_command_line)) )
        kdbx_serial_base = 0x2f8;
    else
        pr_emerg(">>>>>>>>>>>>> kdbx: serial console not setup\n");
    
    if ( cp ) {
        cp += 10;       /* console=ttyS0,115200n8 */
        /* need to check for space before/after the comma */
    }

    return baud;
#endif
}

static char kdbx_console_getc(void)
{
    while ( (inb(kdbx_serial_base + LSR) & RCVRDY) == 0 )
        cpu_relax();

    return (inb(kdbx_serial_base + RXR));
}

static void kdbx_outc(char ch)
{
    while ( (inb(kdbx_serial_base + LSR) & XMTRDY) == 0 )
        cpu_relax();

    outb(ch, kdbx_serial_base + TXR);
}

static void kdbx_console_putc(char ch)
{
    if ( ch == '\n' )
        kdbx_outc('\r');

    kdbx_outc(ch);
}

/* 
 * Code from early_serial_console.c, and early_printk.c.
 * Alternately, we could use cmdline_find_option() to find console= value,
 * or go thru console_cmdline[] to see what has been set in cmdline.
 *
 * https://en.wikibooks.org/wiki/Serial_Programming/8250_UART_Programming
 */
void kdbx_init_console(char *cmdline)
{
    uint divisor, baud;
    unsigned char c;

    /* initialize kdbx_serial_base, kdbx_default_baud, .. */
    kdbx_init_serial_info(cmdline); 
    baud = kdbx_default_baud;

    outb(0x3, kdbx_serial_base + LCR);	/* 8n1 */
    outb(0, kdbx_serial_base + IER);	/* no interrupt */
    outb(0, kdbx_serial_base + FCR);	/* no fifo */
    outb(0x3, kdbx_serial_base + MCR);	/* DTR + RTS */

    divisor = 115200 / baud;
    c = inb(kdbx_serial_base + LCR);
    outb(c | DLAB, kdbx_serial_base + LCR);
    outb(divisor & 0xff, kdbx_serial_base + DLL);
    outb((divisor >> 8) & 0xff, kdbx_serial_base + DLH);
    outb(c & ~DLAB, kdbx_serial_base + LCR);

    kdbxp("kdbx: serial console %s initialized. baud:%d\n", 
          kdbx_serial_base == 0x3f8 ? "COM1/ttyS0" : "COM2/ttyS1", baud);
    /* so it will show up in dmesg also */
    pr_notice("kdbx pr: serial console %s initialized. baud:%d\n", 
              kdbx_serial_base == 0x3f8 ? "COM1/ttyS0" : "COM2/ttyS1", baud);
}

static int kdb_key_valid(int key)
{
    /* note: isspace() is more than ' ', hence we don't use it here */
    if (isalnum(key) || key == ' ' || key == K_BACKSPACE || key == '\n' ||
        key == '?' || key == K_UNDERSCORE || key == '=' || key == '!')
            return 1;
    return 0;
}

/* display kdb prompt and read command from the console 
 * RETURNS: a '\n' terminated command buffer */
char *kdb_get_cmdline(char *prompt)
{
    #define K_BELL     0x7
    #define K_CTRL_C   0x3

    int key, i = 0;

    kdbxp(prompt);
    memset(cmds_a, 0, K_CMD_BUFSZ);
    cmds_a[K_CMD_BUFSZ-1] = '\n';

    while ((__cmpxchg(&kdbxp_gate, 0,1, sizeof(kdbxp_gate)) != 0) && i++ < 2000)
        mdelay(2);

    i = 0;
    do {
        key = kdbx_console_getc();
        if (key == '\r') 
            key = '\n';
        if (key == K_BACKSPACE1) 
            key = K_BACKSPACE;

        if (key == K_CTRL_C || (i==K_CMD_MAXI && key != '\n')) {
            kdbx_console_putc('\n');
            if (i >= K_CMD_MAXI) {
                kdbxp("KDB: cmd buffer overflow\n");
                kdbx_console_putc(K_BELL);
            }
            memset(cmds_a, 0, K_CMD_BUFSZ);
            i = 0;
            kdbxp(prompt);
            continue;
        }
        if (!kdb_key_valid(key)) {
            // kdbx_console_putc(K_BELL);
            continue;
        }
        if (key == K_BACKSPACE) {
            if (i==0) {
                kdbx_console_putc(K_BELL);
                continue;
            } else {
                cmds_a[--i] = '\0';
                kdbx_console_putc(K_BACKSPACE);
                kdbx_console_putc(' ');        /* erase character */
            }
        } else
            cmds_a[i++] = key;

        kdbx_console_putc(key);

    } while (key != '\n');

    kdbxp_gate = 0;

    return cmds_a;
}

/*
 * printk takes a lock, an NMI could come in after that, and another cpu may 
 * spin. also, the console lock is forced unlock, so panic is been seen on 
 * 8 way. hence, no printk() calls.
 */
void kdbxp(const char *fmt, ...)
{
    char buf[256];      /* if you make this static, cmpxchg before vsnprintf */
    va_list args;
    char *p;
    int i=0;

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    while ((__cmpxchg(&kdbxp_gate, 0,1, sizeof(kdbxp_gate)) != 0) && i++ < 3000)
        mdelay(2);

    for (p=buf; *p != '\0'; p++)
        kdbx_console_putc(*p);

    kdbxp_gate = 0;
}

/*
 * copy/read machine memory. 
 * RETURNS: number of bytes copied 
 */
int kdb_read_mmem(kdbma_t maddr, kdbbyt_t *dbuf, int len)
{
    ulong orig = len;

    while (len > 0) {
        ulong pagecnt = min_t(long, PAGE_SIZE - (maddr & ~PAGE_MASK), len);
        struct page *pg = pfn_to_page(maddr >> PAGE_SHIFT);
        char *va = kmap(pg);

        if ( pg == NULL || va == NULL ) {
            kdbxp("kdbx: unable to kmap maddr:%016lx\n", maddr);
            break;
        }

        va = va + (maddr & (PAGE_SIZE-1));        /* add page offset */
        memcpy(dbuf, (void *)va, pagecnt);

        KDBGP1("maddr:%x va:%p len:%x pagecnt:%x\n", maddr, va, len, pagecnt );
        kunmap(pg);

        len = len  - pagecnt;
        maddr += pagecnt;
        dbuf += pagecnt;
    }

    return orig - len;
}

static int kdb_early_rmem(kdbva_t saddr, kdbbyt_t *dbuf, int len)
{
    return (len - __copy_from_user_inatomic((void *)dbuf, (void *)saddr, len));
}

/* RETURNS: number of bytes written */
static int kdb_early_wmem(kdbva_t daddr, kdbbyt_t *sbuf, int len)
{
    return (len - __copy_to_user_inatomic((void *)daddr, sbuf, len));
}

/* given a pfn, map the page and return the pgd/pud/pmd/pte entry at given 
 * offset.
 * returns: 0 if failed (or entry could be 0 also) */
static ulong kdb_lookup_pt_entry(ulong gfn, int idx, struct kvm_vcpu *vp)
{
    ulong rval;
    ulong pfn = kdb_p2m(gfn, vp);
    struct page *pg = pfn_valid(pfn) ? pfn_to_page(pfn) : NULL;
    char *va = pg ? kmap(pg) : NULL;

    KDBGP1("lookup e: gfn:%lx pfn:%lx idx:%x va:%p\n", gfn, pfn, idx, va);
    if ( !pfn_valid(pfn) ) {
        kdbxp("kdb_lookup_pt_entry: pfn:%lx invalid. gfn:%lx vp:%p\n", pfn,
              gfn, vp);
        return 0;
    }

    if ( pg == NULL || va == NULL ) {
        kdbxp("lookup: Unable to map pfn: %lx pg:%p\n", pfn, pg);
        return 0;
    }

    va += idx * 8;
    rval = *(ulong *)va;
    kunmap(pg);
    KDBGP1("lookup e: return entry:%lx\n", rval);

    return rval;
}

/* given a cr3 gfn, walk the pt pointed by the cr3 gfn (could be guest),
 * and return pfn/mfn for the pte gfn */
ulong kdb_pt_pfn(ulong addr, ulong cr3gfn, struct kvm_vcpu *vp, int *levelp)
{
    ulong gfn, entry;

    *levelp = PG_LEVEL_NONE;

    KDBGP1("ptepfn: addr:%lx cr3gfn:%lx vp:%p\n", addr, cr3gfn, vp);
    entry = kdb_lookup_pt_entry(cr3gfn, pgd_index(addr), vp);
    if ( entry == 0 ) {
        kdbxp("pgd not present. cr3gfn:%lx pgdidx:%x vp:%p\n",
              cr3gfn, pgd_index(addr), vp);

        return (ulong)-1;
    }

    *levelp = PG_LEVEL_1G;
    gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    entry = kdb_lookup_pt_entry(gfn, pud_index(addr), vp);
    if ( entry == 0 ) {
        kdbxp("Failed to lookup pud entry. gfn:%lx pudidx:%x vp:%p\n",
              gfn, pud_index(addr), vp);

        return (ulong)-1;
    }
    if ( !pud_present((pud_t){.pud = entry}) ) {
        kdbxp("pud is not present. entry:%lx\n", entry);
        return (ulong)-1;
    }
    if ( pud_large((pud_t){.pud = entry}) )
        goto out;

    *levelp = PG_LEVEL_2M;
    gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    entry = kdb_lookup_pt_entry(gfn, pmd_index(addr), vp);
    if ( entry == 0 ) {
        kdbxp("Failed to lookup pmd entry. gfn:%lx pmdidx:%x vp:%p\n",
              gfn, pmd_index(addr), vp);

        return (ulong)-1;
    }
    if ( !pmd_present((pmd_t){.pmd = entry}) ) {
        kdbxp("pmd is not present. entry:%lx\n", entry);
        return (ulong)-1;
    }
    if ( pmd_large((pmd_t){.pmd = entry}) )
        goto out;

    *levelp = PG_LEVEL_4K;
    gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    entry = kdb_lookup_pt_entry(gfn, pte_index(addr), vp);
    if ( entry == 0 ) {
        kdbxp("Failed to lookup pte entry. gfn:%lx pteidx:%x vp:%p\n",
              gfn, pte_index(addr), vp);

        return (ulong)-1;
    }
    if ( !pte_present((pte_t){.pte = entry}) ) {
        kdbxp("pte is not present. entry:%lx\n", entry);
        return (ulong)-1;
    }

out:
    gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    return kdb_p2m(gfn, vp);
}

/* RETURNS: number of bytes copied */
static int kdb_rw_cr3_mem(kdbva_t addr, kdbbyt_t *buf, int len,
                          struct kvm_vcpu *vp, int toaddr)
{
    ulong cr3gfn;
    int level, orig_len = len;

    if ( vp ) {
        cr3gfn = kdb_get_hvm_field(vp, GUEST_CR3) >> PAGE_SHIFT;
    } else {
        // cr3gfn = (__pa(init_mm.pgd->pgd)) >> PAGE_SHIFT;
        kdbxp("kdb_rw_cr3_mem: guest only, vp must be specified.\n");
        return 0;
    }

    KDBGP1("rw-cr3mem: addr:%lx vp:%p len:%d to:%d cr3gfn:%lx\n", addr, vp, 
           len, toaddr, cr3gfn);

    while (len > 0) {
        ulong pagecnt = min_t(long, PAGE_SIZE - (addr & ~PAGE_MASK), len);
        ulong pfn = kdb_pt_pfn(addr, cr3gfn, vp, &level);
        struct page *pg = pfn_valid(pfn) ? pfn_to_page(pfn) : NULL;
        char *va = pg ? kmap(pg) : NULL;

        if ( !pfn_valid(pfn) ) {
            kdbxp("kdb_rw_cr3_mem: pfn:%lx invalid\n", pfn);
            break;
        }
        if ( pg == NULL || va == NULL ) {
            kdbxp("kdbx: unable to kmap addr:%016lx pfn:%lx\n", addr, pfn);
            break;
        }
        if ( level == PG_LEVEL_1G ) {
            kdbxp("FIXME: 1G Page.. cr3gfn:%lx addr:%lx\n", cr3gfn, addr);
            break;
        } else if ( level == PG_LEVEL_2M )
            va = va + (addr & (PMD_PAGE_SIZE - 1));       /* add page offset */
        else if ( level == PG_LEVEL_4K )
            va = va + (addr & (PAGE_SIZE - 1));           /* add page offset */
        else {
            kdbxp("Unexpected page level: %d cr3gfn:%lx addr:%lx\n", level, 
                  cr3gfn, addr);
            break;
        }

        if ( toaddr )
            memcpy(va, buf, pagecnt);
        else
            memcpy(buf, va, pagecnt);

        KDBGP1("addr:%lx va:%p len:%x pagecnt:%x\n", addr, va, len, pagecnt );
        kunmap(pg);

        len = len  - pagecnt;
        addr += pagecnt;
        buf += pagecnt;
    }

    return orig_len - len;
}

/* RETURNS: number of bytes written */
/*
 * copy/read guest memory
 * RETURNS: number of bytes copied 
 */
int kdb_read_mem(kdbva_t saddr, kdbbyt_t *dbuf, int len, struct kvm_vcpu *vp)
{
    KDBGP2("read mem: saddr:%lx (int)src:%x len:%d vp:%p\n", saddr,
           *(uint *)dbuf, len, vp);

    if ( max_pfn_mapped == 0 )
        return kdb_early_rmem(saddr, dbuf, len);

    if ( vp )
        return kdb_rw_cr3_mem(saddr, dbuf, len, vp, 0);
    else if ( probe_kernel_read((void *)dbuf, (void *)saddr, len) == -EFAULT )
        return 0;

    return len;
}

/*
 * kernel text is protected, so can't use probe_kernel_write.
 * RETURNS: number of bytes written
 */
int kdb_write_protected(kdbva_t daddr, kdbbyt_t *sbuf, int len )
{
    KDBGP2("write mem: addr:%lx (int)src:%lx len:%d\n", daddr,
           *(uint *)sbuf, len);
    text_poke((void *)daddr, (const void *)sbuf, len);

    return (len);
}

/*
 * write guest or host memory. if vp, then guest, else host.
 * RETURNS: number of bytes written
 */
int kdb_write_mem(kdbva_t daddr, kdbbyt_t *sbuf, int len, struct kvm_vcpu *vp)
{
    ulong rc;

    KDBGP2("write mem: addr:%lx (int)src:%lx len:%d vp:%p\n", daddr,
           *(uint *)sbuf, len, vp);

    /* if we are early during boot before init_mem_mapping() */
    if ( max_pfn_mapped == 0 )
        return kdb_early_wmem(daddr, sbuf, len);


    if ( vp == NULL ) {          /* host memory */
        if ( __kernel_text_address(daddr) )
            return kdb_write_protected(daddr, sbuf, len);

        rc = probe_kernel_write((void *)daddr, (void *)sbuf, len);
        if (rc == -EFAULT)
            kdbxp("kdbx memwr -EFAULT: addr:%lx sz:%d\n", daddr, len);

    } else {
        /* guest memory */
        return kdb_rw_cr3_mem(daddr, sbuf, len, vp, 1);
    }

    KDBGP2("write mem rc:%d\n", rc);

    return (len - rc);
}

/* ------------ OLD CODE ---------------------------------------------- */
#if 0

/* when called from main.c:kdbx_init(), neither tty nor console are initialized
 * and both print null. when breaking in upon boot, both are there. 
 * NOTE: early_printk is not initialzed without the early printk grub param.
 */
void kdbx_init_console(void)
{
    struct console *cons;

    kdbx_tty_driver = tty_find_polling_driver("ttyS0", &kdbx_tty_line);
    if (!kdbx_tty_driver) {
        printk(KERN_EMERG "kdbx: unable to find polling driver %s\n",
               kdbx_option);
        return;
    }

    cons = console_drivers;
    while (cons) {
        int idx;

        if (cons->device && cons->device(cons, &idx) == kdbx_tty_driver && 
            idx == kdbx_tty_line) 
        {
            break;
        }
        cons = cons->next;
    }
    if ( cons )
        kdb_console = cons;
    else 
        printk(KERN_EMERG "kdbx: unable to find console\n");

    printk(KERN_EMERG "kdbxinitc: early_cons:%p\n", early_console);
    printk(KERN_EMERG "kdbxtty:%p console:%p\n", kdbx_tty_driver, kdb_console);
}

static char kdbx_console_getc(void)
{
    char c;

    if (!kdbx_tty_driver)
        return -1;

    for (c = 0; ; ) {
        c = kdbx_tty_driver->ops->poll_get_char(kdbx_tty_driver, kdbx_tty_line);
        if ( c )
            break;
        cpu_relax();
    }
    return c;
}

static void kdbx_console_putc(char c)
{
    if (!kdbx_tty_driver)
        return;

     kdbx_tty_driver->ops->poll_put_char(kdbx_tty_driver, kdbx_tty_line, c);
}

// struct tty_driver *kdbx_tty_driver;
// static struct console *kdb_console;
// static int kdbx_tty_line;


    struct console *cons;
pr_emerg("MUK: check for consoles\n");
for_each_console(cons) {
    int idx;
   pr_emerg("MUK: kdbx init: cons->name:%s\n", cons->name);
   if (cons->device) 
         cons->device(cons, &idx);
   pr_emerg("MUK: cons->name:%s idx:%d r:%p w:%p\n", cons->name, idx,
            cons->read, cons->write);

}

    kdbx_tty_driver = tty_find_polling_driver("ttyS0", &kdbx_tty_line);

    if (!kdbx_tty_driver) {
        printk(KERN_EMERG "kdbx: unable to find polling driver %s\n",
               kdbx_option);
        return;
    }

struct tty_driver *driver = kdbx_tty_driver;
        struct uart_driver *drv = driver->driver_state;
        struct uart_state *state = drv->state + line;
        struct uart_port *port;

    pr_emerg("MUK: found tty driver.. \n");
        if (!state || !state->uart_port)
                return ;

        port = state->uart_port;
        pr_emerg("port:%p  port->ops->poll_get_char:%p\n", port,
                 port->ops->poll_get_char);

static int kdbx_mod_init(void)
{
    static int kdbx_tty_line;
    struct tty_driver *kdbx_tty_driver;

    kdbxp(">>>>>>>>>> kdbx_init()\n");

    kdbx_tty_driver = tty_find_polling_driver("ttyS0", &kdbx_tty_line);
    if (!kdbx_tty_driver) {
        kdbxp(">>>>>>>>>>>>>> unable to find tty_driver\n");
        return 0;
    } 
    return 0;
}

static void kdbx_mod_exit(void)
{
}

module_init(kdbx_mod_init)
module_exit(kdbx_mod_exit)

#endif
