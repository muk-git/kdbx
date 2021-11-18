/*
 * Copyright (C) 2009, 2020 Mukesh Rathor, Oracle Corp.  All rights reserved.
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

static char kdbx_getc(void);
static void kdbx_outc(char ch);

#ifdef KDBX_CONFIG_SWITCH_TO_TTY
static char tty_kdbx_getc(void);
static int kdbx_tty_line;
static struct tty_driver *kdbx_tty_driver;
#endif

static int kdbx_serial_base;   /* com1/ttyS0: 3f8, ttyS1: 2f8 */
static int kdbx_serial_irq;    /* com1/ttyS0: 4  ttyS1: 3 */
static int kdbx_serial_baud=115200;   /* 115200/57600/28800/14400... */

#ifndef CONFIG_SERIAL_8250

static struct tty_driver *kdbx_tty_drv;

static void kdbx_cons_write(struct console *co, const char *s, uint count);
static struct tty_driver *kdbx_cons_ttydev(struct console *co, int *index);
static struct tty_port kdbx_tty_port;

static struct console kdbx_cons = {
        .name           = "ttyS",
        .write          = kdbx_cons_write,
        .device         = kdbx_cons_ttydev,
        .setup          = NULL,
        .match          = NULL,
        .flags          = CON_PRINTBUFFER | CON_ANYTIME | CON_ENABLED,
        .index          = -1,
        .data           = NULL,
};

static void kdbx_cons_write(struct console *co, const char *s, uint count)
{
    int i;

    for (i=0; i < count; i++)
        kdbxp("%c", s[i]);
}

static struct tty_driver *kdbx_cons_ttydev(struct console *co, int *index)
{
    if ( co == &kdbx_cons && *index == kdbx_cons.index)
        return kdbx_tty_drv;
    else
        return NULL;
}

static int __init kdbx_console_init(void)
{
    register_console(&kdbx_cons);
    return 0;
}
console_initcall(kdbx_console_init);  /* called before kdbx_tty_init */


static const struct tty_port_operations kdbx_tty_portops;

static int kdbx_tty_open(struct tty_struct *tty, struct file *filp)
{
    int rc;

    filp->f_flags |= O_NONBLOCK;    /* don't ever let it block */
    rc = tty_port_open(tty->port, tty, filp);
    if ( rc ) {
        kdbxp("kdbx: failed to open tty port:%px\n", tty->port);
        return rc;
    }
    return 0;
}

static void kdbx_tty_close(struct tty_struct *tty, struct file *filp)
{
    tty_port_close(tty->port, tty, filp);
}

/* Return the number of bytes that can be queued to this device */
static int kdbx_write_room(struct tty_struct *tty)
{
    return 1;
}

static int kdbx_tty_write(struct tty_struct *tty,
                           const unsigned char *buf, int count)
{
    int i;

    for (i=0; i < count; i++)
        kdbxp("%c", buf[i]);
    return count;
}

static int kdbx_tty_put_char(struct tty_struct *tty, unsigned char c)
{
    kdbxp("%c", c);
    return 1;
}


/* do man termios to see the meaning of the flags */
static struct ktermios kdbx_tty_termios = {
    .c_iflag = IGNBRK | IGNPAR,
    .c_oflag = 0,
    .c_cflag = B115200 | CS8 | CREAD | CLOCAL,
    .c_lflag = 0,
    .c_cc = {0},        /* what are the control flags */
};

/* systemd etc will set termios and set OPOST and other flags and mess it
 * up, don't let them. called from tty_ioctl.c:tty_set_termios().
 * NOTE: old_termios is not the original kdbx_tty_termios 
 */
static void kdbx_tty_set_termios(struct tty_struct *tty,
                                 struct ktermios *old_termios)
{
    tty->termios = kdbx_tty_termios;
}

static void kdbx_tty_hangup(struct tty_struct *tty)
{
    tty_port_hangup(tty->port);
}

static int kdbx_tty_ioctl(struct tty_struct *tty, unsigned int cmd, 
                          unsigned long arg) 
{
    // kdbxp(">>>>> ttyioctl: 0x%x ioerr:%d\n", cmd, tty_io_error(tty));
    return -ENOIOCTLCMD;
}

/* see drivers/tty/tty_ioctl.c for deatils on these ops */
static struct tty_operations kdbx_tty_ops = {
        .open           = kdbx_tty_open,
        .close          = kdbx_tty_close,
        .write          = kdbx_tty_write,
        .put_char       = kdbx_tty_put_char,
        .ioctl          = kdbx_tty_ioctl,
        .set_termios    = kdbx_tty_set_termios,
        .hangup         = kdbx_tty_hangup,
        .write_room     = kdbx_write_room,
#if 0
        .flush_chars    = kdbx_tty_flush_chars,
        .chars_in_buffer= uart_chars_in_buffer,
        .flush_buffer   = uart_flush_buffer,
        .throttle       = uart_throttle,
        .unthrottle     = uart_unthrottle,
        .send_xchar     = uart_send_xchar,
        .set_ldisc      = uart_set_ldisc,
        .stop           = uart_stop,
        .start          = uart_start,
        .break_ctl      = uart_break_ctl,
        .wait_until_sent= uart_wait_until_sent,
#ifdef CONFIG_PROC_FS
        .proc_fops      = &uart_proc_fops,
#endif
        .tiocmget       = uart_tiocmget,
        .tiocmset       = uart_tiocmset,
        .get_icount     = uart_get_icount,
#ifdef CONFIG_CONSOLE_POLL
        .poll_init      = uart_poll_init,
        .poll_get_char  = uart_poll_get_char,
        .poll_put_char  = uart_poll_put_char,
#endif
#endif /* #if 0 */
};

/* called after kdbx_console_init */
static int __init kdbx_tty_init(void)
{
    int rc;
    struct tty_driver *tty_driver = alloc_tty_driver(1);

    if ( tty_driver == NULL ) {
        kdbxp("kdbx: Failed to alloc_tty_driver\n");
        return -ENOMEM;
    }

    tty_driver->owner = THIS_MODULE;
    tty_driver->driver_name = "kdbx-serial";
    tty_driver->name = "ttyS";         /* will appear as /dev/"ttyS"%d */
    tty_driver->major = TTY_MAJOR;
    tty_driver->minor_start = 64;
    tty_driver->type = TTY_DRIVER_TYPE_SERIAL;
    tty_driver->subtype = SERIAL_TYPE_NORMAL;
    tty_driver->flags = TTY_DRIVER_REAL_RAW;
    // tty_driver->init_termios = tty_std_termios;
    tty_driver->init_termios = kdbx_tty_termios;
    tty_driver->init_termios.c_ispeed = kdbx_serial_baud;
    tty_driver->init_termios.c_ospeed = kdbx_serial_baud;
    tty_set_operations(tty_driver, &kdbx_tty_ops); /* set tty_driver->ops */

    memset(&kdbx_tty_port, 0, sizeof(kdbx_tty_port));
    tty_port_init(&kdbx_tty_port);
    kdbx_tty_port.ops = &kdbx_tty_portops;
    tty_port_set_initialized(&kdbx_tty_port, 1);
    tty_port_link_device(&kdbx_tty_port, tty_driver, 0);

    if ( (rc = tty_register_driver(tty_driver)) < 0 ) {
        kdbxp("kdbx: failed to register tty driver. rc:%d\n", rc);
        put_tty_driver(tty_driver);
        return rc;
    }
    kdbx_tty_drv = tty_driver;
    kdbxp(">> kdbx: Yay! tty init done\n");
    return 0;
}

#endif /* CONFIG_SERIAL_8250 */


/* ====================== 8250 stuff ===================================== */
/* https://www.activexperts.com/serial-port-component/tutorials/uart/
 * https://en.wikibooks.org/wiki/Serial_Programming/8250_UART_Programming
 *
 * TBD: we run in polling mode. IER, interrupt mode, is disabled so in case of
 *      data in, the UART will not interrupt us. When breaking into KDBX, add 
 *      code to disable IER if it's enabled by the tty drivers, then restore it.
 *      Done by serial tty driver.
 *
 * REFERENCES: setup_early_printk() and univ8250_console_setup()
 */

/* A UART has 8 registers. reg 0 is used for both xmit and receive. */
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


/* called from do_nmi() */
void kdbx_dump_uart(void)
{
    kdbxp(">>>> UART: IER: %x LCR:%x ISR:%x LSR:%x MSR:%x MCR:%x\n",
          inb(kdbx_serial_base + REG_IER), inb(kdbx_serial_base + REG_LCR),
          inb(kdbx_serial_base + REG_ISR), inb(kdbx_serial_base + REG_LSR),
          inb(kdbx_serial_base + REG_MSR), inb(kdbx_serial_base + REG_MCR)); 
}

/* parse the cmd line for ttyS port/index, baud rate etc.. */
static noinline int kdbx_parse_cmdline(char *cmdline)
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
#ifndef CONFIG_SERIAL_8250
        kdbx_cons.index = 0;
#endif
    } else if ( *p == '1' ) {
        kdbx_serial_base = 0x2f8;  /* ttyS1 */
        kdbx_serial_irq = 3;
#ifndef CONFIG_SERIAL_8250
        kdbx_cons.index = 1;
#endif
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
        kdbx_serial_baud = 115200;
    else if ( strstr(p, "57600") )
        kdbx_serial_baud = 57600;
    else if ( strstr(p, "28800") )
        kdbx_serial_baud = 28800;
    else if ( strstr(p, "14400") )
        kdbx_serial_baud = 14400;
    else if ( strstr(p, "7200") )
        kdbx_serial_baud = 7200;
    else if ( strstr(p, "3600") )
        kdbx_serial_baud = 3600;
    else {
        kdbx_serial_baud = 115200;
        pr_notice(">>>>>> kdbx: %s baud not found/recognized. default:%d\n",
                  p, kdbx_serial_baud);
    }
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

    baud = kdbx_serial_baud;

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

/* early boot setup_arch -> kdbx_init -> kdbx_init_io */
void kdbx_init_io(char *cmdline)
{
    /* initialize kdbx_serial_base, kdbx_serial_baud, .. */
    if ( kdbx_parse_cmdline(cmdline) )
        return;

    kdbx_init_early_serial();
}


#ifndef CONFIG_SERIAL_8250 

/* See https://www.activexperts.com/serial-port-component/tutorials/uart/
 *
 * REF: serial8250_handle_irq() -> serial8250_rx_chars() -> serial8250_read_char
 * TBD: check for UART_LSR_BI for serial over lan
 */
irqreturn_t kdbx_serial8250_irq_handler(int irq, void *dev_id)
{
    char ch;

    /* see: serial8250_read_char() */
    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_RCVRDY) ) {
        ch = inb(kdbx_serial_base + REG_RXR);
        if ( ch == 0x1c )
            kdbx_keyboard(get_irq_regs());
#if 0
        else {
            tty_insert_flip_char(&kdbx_tty_port, ch, TTY_NORMAL);
        }
        tty_flip_buffer_push(&kdbx_tty_port);
#endif
    }
    return IRQ_HANDLED;
}

static void kdbx_setup_serial_irq(void)
{
    int ret;

    ret = request_irq(kdbx_serial_irq, kdbx_serial8250_irq_handler, 0, 
                      "kdbxS0", NULL);
    if ( ret != 0 ) {
        kdbxp(">>>>>> kdbx: request_irq failed. ret:%d\n", ret);
        return;
    }
    /* Enable interrupts on the UART so ctrl+\ will work */
    outb(IER_RXRDY, kdbx_serial_base + REG_IER);
    outb(MCR_RTS|MCR_OUT2, kdbx_serial_base + REG_MCR);

    kdbxp(">>>>>> kdbx: UART ints enabled\n");
    // kdbx_dump_uart();
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

/* register device driver for uart device on the bus, so we can set irq */
static int __init kdbx_register_8250_setup_irq(void)
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

static int __init kdbx_uart_init(void)
{
    kdbx_register_8250_setup_irq(); /* could move this to kdbx_console_init */
    kdbx_tty_init();
    return 0;
}

static void __exit kdbx_uart_exit(void)
{
    kdbxp("kdbx_uart_exit\n");
}

module_init(kdbx_uart_init);    /* called after kdbx_console_init */
module_exit(kdbx_uart_exit);

#endif /* CONFIG_SERIAL_8250 */


/* input a char */
static char kdbx_getc(void)
{
#ifdef KDBX_CONFIG_SWITCH_TO_TTY
    /* before tty is set, we wanna do IO thru early serial emulated by qemu */
    if ( kdbx_tty_driver ) {
        return tty_kdbx_getc();
    }
#endif

    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_RCVRDY) == 0 )
        kdbx_cpu_relax();

    return (inb(kdbx_serial_base + REG_RXR));
}

static void kdbx_outc(char ch)
{
#ifdef KDBX_CONFIG_SWITCH_TO_TTY
    /* before tty is set, we wanna do IO thru early serial emulated by qemu */
    if ( kdbx_tty_driver ) {
        kdbx_tty_driver->ops->poll_put_char(kdbx_tty_driver, kdbx_tty_line, ch);
        return;
    }
#endif

    while ( (inb(kdbx_serial_base + REG_LSR) & LSR_XMTRDY) == 0 )
        kdbx_cpu_relax();

    outb(ch, kdbx_serial_base + REG_TXR);
}

static void kdbx_print_char(char ch)
{
    if ( ch == '\n' )
        kdbx_outc('\r');

    kdbx_outc(ch);
}


#define K_BACKSPACE  0x8                   /* ctrl-H */
#define K_BACKSPACE1 0x7f                  /* ctrl-? */
#define K_UNDERSCORE 0x5f
#define K_CMD_BUFSZ  160
#define K_CMD_MAXI   (K_CMD_BUFSZ - 1)     /* max index in buffer */

static volatile int kdbxp_gate = 0;
static char cmds_a[K_CMD_BUFSZ];

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
        key = kdbx_getc();
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

/*
 * printk takes a lock, an NMI could come in after that, and another cpu may 
 * spin. also, the console lock is forced unlock, so panic is been seen on 
 * 8 way. hence, no printk() calls.
 */
void kdbxp(char *fmt, ...)
{
    va_list args;
    char buf[1024];     /* if you make this static, cmpxchg before vsnprintf */
    int num, i=0;

    while ((__cmpxchg(&kdbxp_gate, 0,1, sizeof(kdbxp_gate)) != 0) && i++ < 3000)
        mdelay(2);

    va_start(args, fmt);
    num = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    for (; i < num; i++)
        kdbx_print_char(buf[i]);

    kdbxp_gate = 0;
}

/* ======================================================================== */

#ifndef KDBX_CONFIG_SWITCH_TO_TTY
void kdbx_switch_to_tty(void)
{
}
#endif

#ifdef CONFIG_SERIAL_8250
#ifdef KDBX_CONFIG_SWITCH_TO_TTY

/* 
 * kdbx/Makefile:  KBUILD_CPPFLAGS +=-DKDBX_CONFIG_SWITCH_TO_TTY
 * serial/8250/8250_core.c: serial8250_init() add kdbx_switch_to_tty at the
 *                          very end.
 */

void kdbx_switch_to_tty(void)
{
    kdbx_tty_driver = tty_find_polling_driver("ttyS0", &kdbx_tty_line);
    if (!kdbx_tty_driver) {
        kdbxp(">>>>> kdbx: unable to find polling driver \n");
        printk(KERN_EMERG "kdbx: unable to find polling driver \n");
        return;
    }
    kdbxp(">> kdbx: switch to tty driver:%px\n", kdbx_tty_driver);
    pr_notice(">>>>>>kdbx: switch to tty driver:%px\n", kdbx_tty_driver);
}

static char tty_kdbx_getc(void)
{
    char c = 0;
    while ( c == 0 ) {
        c = kdbx_tty_driver->ops->poll_get_char(kdbx_tty_driver, kdbx_tty_line);
        if ( c == 0 )
            kdbx_cpu_relax();
    }
    return c;
}

#endif /* KDBX_CONFIG_SWITCH_TO_TTY */
#endif /* CONFIG_SERIAL_8250 */

/* ======================================================================== */

#ifdef CONFIG_KDBX_FOR_XEN_DOM0

/* #if 0 out above non dom0 definitions */

/* we are running as dom0 on xen, and don't need to do anything */
void kdbx_init_io(char *cmdline)
{
}

static char kdbx_getc(void)
{
    char ch;

    /* can't call console function because when key typed, xen will inject
     * virq into dom0 and the handler, hvc_poll() will get called and
     * inject key into tty */
    while (dom0_read_console(0, &ch, 1) <= 0 )
        kdbx_cpu_relax();

    return ch;
}

static void kdbx_outc(char ch)
{
    // printk(KERN_EMERG "%c", ch);
    dom0_write_console(0, &ch, 1);
}
#endif /* CONFIG_KDBX_FOR_XEN_DOM0 */

/* ======================================================================== */










#if 00000000000000000000000000000000000000000000000000   /* OLD stuff */
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


#endif /* if 0 */
