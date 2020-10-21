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

static volatile int kdbxp_gate = 0;
static char cmds_a[K_CMD_BUFSZ];
static void kdbx_print_char(char);
static char kdbx_cmd_getc(void);
static void kdbx_outc(char ch);

#ifndef CONFIG_KDBX_FOR_XEN_DOM0

static int kdbx_serial_base = 0x3f8;  /* default to com1/ttyS0 */
static int kdbx_serial_irq = 4;       /* default for com1 */
static int kdbx_default_baud = 115200;    /* default to  115200 */

/* A UART has 8 registers. reg 0 is used for both xmit and receive.
 *    https://www.activexperts.com/serial-port-component/tutorials/uart/ 
 */
#define REG_TXR             0       /*  Transmit register */
#define REG_RXR             0       /*  Receive register */
#define REG_IER             1       /*  Interrupt Enable register */
#define REG_ISR             2       /*  Interrupt status register */
#define REG_LCR             3       /*  Line control register */
#define REG_MCR             4       /*  Modem control register */
#define REG_LSR             5       /*  Line Status register */
#define REG_MSR             6       /*  Modem Status register */

#define IER_RXRDY     0x01  /* interrupt when a char is received in RXR */
#define IER_TXRDY     0x02  /* interrupt when a char is moved out of TXR */
#define IER_LineError 0x04  /* interrupt when there is line/parity error */
#define IER_MSI       0x08  /* interrupt when any rs232 line change state */

#define MCR_RTS       0x2
#define MCR_OUT2      0x8

/* LSR stores general status about the UART */
#define LSR_RCVRDY   0x01    /* RXR has a character to be read */
#define LSR_OVRRUN   0x02    /* prev char in RXR over run */
#define LSR_PARITY   0x04    /* parity error */
#define LSR_XMTRDY   0x20    /* TXR empty, ready to receive next char */

#define LCR_DLAB	0x80    /* when set, reg 0 and 1 have special meaning */
#define LCR_DLL         0       /*  Divisor Latch Low         */
#define LCR_DLH         1       /*  Divisor latch High        */

/*
 * https://www.activexperts.com/serial-port-component/tutorials/uart/
 * https://en.wikibooks.org/wiki/Serial_Programming/8250_UART_Programming
 *
 * TBD: we run in polling mode. IER, interrupt mode, is disabled so in case of
 *      data in, the UART will not interrupt us. When breaking into KDBX, add 
 *      code to disable IER if it's enabled by the tty drivers, then restore it.
 *      Done by serial tty driver.
 *
 * REFERENCES: setup_early_printk() and univ8250_console_setup()
 */
static int kdbx_init_serial_info(char *cmdline)
{
    char *p = strstr(cmdline, "ttyS");

    if ( p == NULL ) {
        pr_notice(">>> kdbx: console= in cmdline not set.... \n");
        return -1;
    }

    /* parse : console=ttyS0,115200n8 */
    p += 4;
    if ( *p == '0' ) {
        kdbx_serial_base = 0x3f8;  /* ttyS0 */
        kdbx_serial_irq = 4;
    } else if ( *p == '1' ) {
        kdbx_serial_base = 0x2f8;  /* ttyS1 */
        kdbx_serial_irq = 3;
    } else {
        pr_notice(">>> kdbx: ttyS%c in cmdline not recognized\n", *p);
        return -1;
    }
    p++;
    if ( *p == ',' )
        p++;
    else
        return 0;

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
        pr_notice(">>>>>> kdbx: %s baud not recognized. default:%d\n",
                  p, kdbx_default_baud);

    return 0;
}

/* 
 * From kdbx_init():
 *   - early_console is NULL (unless set in grub line)
 *   - tty_find_polling_driver() returns NULL for both ttyS0 and S1
 *   - console_drivers == NULL
 *
 * pr_notice():  -> vprintk_default() -> vprintk_emit() -> 
 *                     call_console_drivers() -> console_unlock() just returns
 *
 * Without earlyprink: output of pr_notice goes to printk buffer, and when
 * start_kernel() -> console_init() is called, it is flushed.
 *
 * With earlyprintk=ttyS0 : output goes to printk buffer,  and when 
 *    start_kernel() -> setup_arch() -> parse_early_param(), which is much
 *    before console_init(), but after kdbx_init(), output is out to ttyS0.
 *
 * Order: kdbx_init, then early_printk, then console_init, then way later
 *        tty setup (tty_find_polling_driver will return null till then).
 *
 */
static void kdbx_init_early_serial(void)
{
    uint divisor, baud;
    unsigned char c;

    baud = kdbx_default_baud;

    outb(0x3, kdbx_serial_base + REG_LCR);	/* 8n1 */
    outb(0, kdbx_serial_base + REG_IER);	/* no interrupt */
    outb(0, kdbx_serial_base + REG_ISR);	/* no fifo */
    outb(0x3, kdbx_serial_base + REG_MCR);	/* DTR + RTS */

    divisor = 115200 / baud;
    c = inb(kdbx_serial_base + REG_LCR);
    outb(c | LCR_DLAB, kdbx_serial_base + REG_LCR);   /* to set divisor */
    outb(divisor & 0xff, kdbx_serial_base + LCR_DLL);
    outb((divisor >> 8) & 0xff, kdbx_serial_base + LCR_DLH);
    outb(c & ~LCR_DLAB, kdbx_serial_base + REG_LCR); /* divisor set is done */

    kdbxp(">>>> kdbx: serial console %s initialized. baud:%d\n", 
          kdbx_serial_base == 0x3f8 ? "COM1/ttyS0" : "COM2/ttyS1", baud);

    /* so it will show up on other consoles also */
    // pr_notice("kdbx pr: serial console %s initialized. baud:%d\n", 
              // kdbx_serial_base == 0x3f8 ? "COM1/ttyS0" : "COM2/ttyS1", baud);
}

/* called from do_nmi() */
void kdbx_dump_uart(void)
{
    kdbxp(">>>> UART: IER: %x LCR:%x ISR:%x LSR:%x MSR:%x MCR:%x\n",
          inb(kdbx_serial_base + REG_IER), inb(kdbx_serial_base + REG_LCR),
          inb(kdbx_serial_base + REG_ISR), inb(kdbx_serial_base + REG_LSR),
          inb(kdbx_serial_base + REG_MSR), inb(kdbx_serial_base + REG_MCR)); 
}

void kdbx_init_io(char *cmdline)
{
    /* initialize kdbx_serial_base, kdbx_default_baud, .. */
    if ( kdbx_init_serial_info(cmdline) )
        return;

    kdbx_init_early_serial();

    /* flush the UART for any input. It buffers even on reset. */
    /* TBD: DOESN'T SEEM TO HELP: may be reset 8250 ? */
    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_RCVRDY) )
        inb(kdbx_serial_base + REG_RXR);
}


uint kdbx_sav_ier, kdbx_sav_mcr;

void kdbx_disable_8250_ints(void)
{
    kdbx_sav_ier = inb(kdbx_serial_base + REG_IER);
    kdbx_sav_mcr = inb(kdbx_serial_base + REG_MCR);
    outb(0, kdbx_serial_base + REG_IER);    /* disable 8250 interrupts */
}

void kdbx_enable_8250_ints(void)
{
    outb(kdbx_sav_ier, kdbx_serial_base + REG_IER);/* restore 8250 interrupts */
    outb(kdbx_sav_mcr, kdbx_serial_base + REG_MCR);/* restore mcr. needed?? */
}

/* ========================================================================= */
#ifndef CONFIG_SERIAL_8250

/* see https://www.activexperts.com/serial-port-component/tutorials/uart/ */
irqreturn_t kdbx_serial8250_irq_handler(int irq, void *dev_id)
{
    char ch;

    /* swallow any uninteresting characters */
    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_RCVRDY) )
        if ( (ch = inb(kdbx_serial_base + REG_RXR)) == 0x1c )
            break;
#if 0
    if ( (inb(kdbx_serial_base + REG_LSR) & LSR_RCVRDY) )
        ch = inb(kdbx_serial_base + REG_RXR);
    else {
        kdbxp(">>>>>> kdbx irq: no LSR, ignoring IRQ:%d\n", irq);
        goto out;
    }
#endif
    if ( ch == 0x1c ) {
        kdbx_disable_8250_ints();
        kdbx_keyboard(get_irq_regs());
        kdbx_enable_8250_ints();
    }

    return IRQ_HANDLED;
}

static void kdbx_setup_serial_irq(void)
{
    int ret;

    ret = request_irq(kdbx_serial_irq, kdbx_serial8250_irq_handler, 0, 
                      "kdbxS0", NULL);
    if ( ret != 0 )
        kdbxp(">>>>>> kdbx: request_irq failed. ret:%d\n", ret);

    /* Enable interrupts on the UART so ctrl+\ will work */
    outb(IER_RXRDY, kdbx_serial_base + REG_IER);
    outb(MCR_RTS|MCR_OUT2, kdbx_serial_base + REG_MCR);

    kdbxp(">>>>>> kdbx: UART ints enabled\n");
    kdbx_dump_uart();
}

static const struct old_serial_port kdbx_old_serinfo[] = {
        SERIAL_PORT_DFNS /* defined in asm/serial.h */
};

/* see also: serial8250_probe() -..--> serial8250_config_port()
 * struct platform_device: include/linux/platform_device.h
 */
static int kdbx_register_8250_device(void)
{
    int i, sz = 0;
    struct old_serial_port *op = (struct old_serial_port *)&kdbx_old_serinfo[0];

    for ( i=0; i < ARRAY_SIZE(kdbx_old_serinfo); i++, op++ ) {
        if ( op->port == kdbx_serial_base )
            break;
    }
    if ( i >= ARRAY_SIZE(kdbx_old_serinfo) ) {
        kdbxp(">>>>> kdbx: could not find serial_base in old_serial:%x\n",
              kdbx_serial_base);
        return -EINVAL;
    }

    kdbx_serial_irq = op->irq;
    if ( kdbx_serial_irq != 3 && kdbx_serial_irq != 4 ) {
        kdbxp(">>>>>kdbx_serial8250_probe: Unexpected IRQ:%d\n", op->irq);
        return -EINVAL;
    }
    sz = 8 << op->iomem_reg_shift;    /* serial8250_port_size() */
    if ( sz == 0 ) {
        kdbxp(">>>> kdbx_serial8250_probe: ERROR region size is 0?\n");
        return -EINVAL;
    }

    kdbxp(">>>>>>kdbx register serial: iobase:%x irq:%x regsize:%d\n",
          kdbx_serial_base, kdbx_serial_irq, sz);

    if ( !request_region(kdbx_serial_base, sz, "serial") ) {
        kdbxp(">>>>> kdbx_serial8250_probe: unable to req region\n");
        return -EBUSY;
    }

    return 0;
}

static int kdbx_serial8250_probe(struct platform_device *dev)
{
    kdbxp(">>>> KDBX: kdbx_serial8250_probe. ret 0\n");
    return 0;
}
static int kdbx_serial8250_remove(struct platform_device *dev)
{
    kdbxp(">>>> KDBX: refusing to remove 8250 driver\n");
    return 0;
}

static struct platform_device *kdbx_serial8250_isa_devs;

static struct platform_driver kdbx_serial8250_isa_driver = {
        .probe          = kdbx_serial8250_probe,
        .remove         = kdbx_serial8250_remove,
        .driver         = {
                .name   = "serial8250",
                .owner  = THIS_MODULE,
        },
};

/* register device driver for uart device on the bus */
static int __init kdbx_serial8250_init(void)
{
        int ret = 0;

        kdbx_serial8250_isa_devs = platform_device_alloc("serial8250",
                                                         PLAT8250_DEV_LEGACY);
        if (!kdbx_serial8250_isa_devs) {
                kdbxp(">>>>> kdbx_serial8250_init dev alloc failed\n");
                return -ENOMEM;
        }
        ret = platform_device_add(kdbx_serial8250_isa_devs);
        if (ret) {
            kdbxp(">>>>> kdbx_serial8250_init: dev add failed. ret:%d\n", ret);
            platform_device_put(kdbx_serial8250_isa_devs);
            return ret;
        }

        if ( (ret = kdbx_register_8250_device()) ) {
            platform_device_put(kdbx_serial8250_isa_devs);
            return ret;
        }
        ret = platform_driver_register(&kdbx_serial8250_isa_driver);
        if (ret) {
            platform_device_del(kdbx_serial8250_isa_devs);
            platform_device_put(kdbx_serial8250_isa_devs);
        }

        kdbx_setup_serial_irq();

        return ret;
}

module_init(kdbx_serial8250_init);


static void kdbx_console_write(struct console *co, const char *s, uint num)
{
        while (num--)
            kdbx_print_char(*s++);
}

static struct console kdbx_console = {
        .name           = "kdbxS",
        .write          = kdbx_console_write,
        .flags          = CON_PRINTBUFFER | CON_ANYTIME | CON_ENABLED,
};

/* add kdbx console so that all udev and init process who write to console
 * can have their output on xterm */
static int __init kdbx_console_init(void)
{
        register_console(&kdbx_console);
        return 0;
}
console_initcall(kdbx_console_init);
#endif /* ifndef CONFIG_SERIAL_8250 */

static char kdbx_cmd_getc(void)
{
    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_RCVRDY) == 0 )
        cpu_relax();

    return (inb(kdbx_serial_base + REG_RXR));
}

static void kdbx_outc(char ch)
{
    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_XMTRDY) == 0 )
        cpu_relax();

    outb(ch, kdbx_serial_base + REG_TXR);
}

#else   /* CONFIG_KDBX_FOR_XEN_DOM0 */

/* we are running as dom0 on xen, and don't need to do anything */
void kdbx_init_io(char *cmdline)
{
}

static char kdbx_cmd_getc(void)
{
    char ch;

    /* can't call console function because when key typed, xen will inject 
     * virq into dom0 and the handler, hvc_poll() will get called and 
     * inject key into tty */
    while (dom0_read_console(0, &ch, 1) <= 0 )
        cpu_relax();

    return ch;
}

static void kdbx_outc(char ch)
{
    // printk(KERN_EMERG "%c", ch);
    dom0_write_console(0, &ch, 1);
}

#endif /* CONFIG_KDBX_FOR_XEN_DOM0 */


static void kdbx_print_char(char ch)
{
    if ( ch == '\n' )
        kdbx_outc('\r');

    kdbx_outc(ch);
}
static int kdb_key_valid(int key)
{
    /* note: isspace() is more than ' ', hence we don't use it here */
    if (isalnum(key) || key == ' ' || key == K_BACKSPACE || key == '\n' ||
        key == '?' || key == K_UNDERSCORE || key == '=' || key == '!' ||
        key == '.' )
    {
        return 1;
    }
    return 0;
}

/* display kdb prompt and read command from the console 
 * RETURNS: a '\n' terminated command buffer */
char *kdbx_get_input(char *prompt)
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
        key = kdbx_cmd_getc();
        if (key == '\r') 
            key = '\n';
        if (key == K_BACKSPACE1) 
            key = K_BACKSPACE;

        if (key == K_CTRL_C || (i==K_CMD_MAXI && key != '\n')) {
            kdbx_print_char('\n');
            if (i >= K_CMD_MAXI) {
                kdbxp("KDB: cmd buffer overflow\n");
                kdbx_print_char(K_BELL);
            }
            memset(cmds_a, 0, K_CMD_BUFSZ);
            i = 0;
            kdbxp(prompt);
            continue;
        }
        if (!kdb_key_valid(key)) {
            // kdbx_print_char(K_BELL);
            continue;
        }
        if (key == K_BACKSPACE) {
            if (i==0) {
                kdbx_print_char(K_BELL);
                continue;
            } else {
                cmds_a[--i] = '\0';
                kdbx_print_char(K_BACKSPACE);
                kdbx_print_char(' ');        /* erase character */
            }
        } else
            cmds_a[i++] = key;

        kdbx_print_char(key);

    } while (key != '\n');

    kdbxp_gate = 0;

    return cmds_a;
}

int kdbx_kernel_printk(char *fmt, va_list args)
{
    char buf[1024];     /* if you make this static, cmpxchg before vsnprintf */
    int num, i=0;

    num = vscnprintf(buf, sizeof(buf), fmt, args);
    if (printk_get_level(buf))
        i = 1;

    while ((__cmpxchg(&kdbxp_gate, 0,1, sizeof(kdbxp_gate)) != 0) && i++ < 3000)
        mdelay(2);

    for (; i < num; i++)
        kdbx_print_char(buf[i]);

    kdbxp_gate = 0;

    return num;
}

/*
 * printk takes a lock, an NMI could come in after that, and another cpu may 
 * spin. also, the console lock is forced unlock, so panic is been seen on 
 * 8 way. hence, no printk() calls.
 */
void kdbxp(char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    kdbx_kernel_printk(fmt, args);
    // (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
}

/* ======================================================================== */
#ifdef KDBX_CONFIG_SWITCH_TO_TTY

/*
  1. in kdbx/Makefile add:
     KBUILD_CPPFLAGS +=-DKDBX_CONFIG_SWITCH_TO_TTY

  2. Add a call to kdbx_switch_to_tty() at the very end in serial8250_init()
     in serial/8250/8250_core.c
*/

static int kdbx_tty_line;
static struct tty_driver *kdbx_tty_driver;

void kdbx_switch_to_tty(void)
{
    kdbx_tty_driver = tty_find_polling_driver("ttyS0", &kdbx_tty_line);
    if (!kdbx_tty_driver) {
        kdbxp(">>>>> kdbx: unable to find polling driver \n");
        printk(KERN_EMERG "kdbx: unable to find polling driver \n");
        return;
    }

    kdbxp(">> kdbx: switch to tty driver:%p\n", kdbx_tty_driver);
    pr_notice(">>>>>>kdbx: switch to tty driver:%p\n", kdbx_tty_driver);
}

static char kdbx_cmd_getc(void)
{
    char c = 0;

    if ( likely(kdbx_tty_driver) ) {
        while ( c == 0 ) {
            c = kdbx_tty_driver->ops->poll_get_char(kdbx_tty_driver, 
                                                    kdbx_tty_line);
            if ( c == 0 )
                cpu_relax();
        }
        return c;
    }

    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_RCVRDY) == 0 )
        cpu_relax();

    return (inb(kdbx_serial_base + REG_RXR));
}

static void kdbx_outc(char ch)
{
    if ( likely(kdbx_tty_driver) ) {
        kdbx_tty_driver->ops->poll_put_char(kdbx_tty_driver, kdbx_tty_line, ch);
        return;
    }

    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_XMTRDY) == 0 )
        cpu_relax();

    outb(ch, kdbx_serial_base + REG_TXR);
}

#endif /* KDBX_CONFIG_SWITCH_TO_TTY */

