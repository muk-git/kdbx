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

#ifndef _KDBINC_H
#define _KDBINC_H

#include <asm/ptrace.h>
#include <asm/traps.h>                  /* dotraplinkage, ...           */

#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <asm/nmi.h>
#include <asm/desc_defs.h>
#include <asm/desc.h>
#include <asm/bootparam.h>
#include <asm/apic.h>
#include <asm/smp.h>
#include <asm/page.h>
#include <asm/timer.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/console.h>
#include <linux/vt_kern.h>
#include <linux/ctype.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/nmi.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/export.h>
#include <linux/memory.h>
#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
#include <linux/bootmem.h>
#endif
#include <linux/memblock.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
#include <linux/kmemcheck.h>
#endif
#include <linux/suspend.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/oom.h>
#include <linux/notifier.h>
#include <linux/topology.h>
#include <linux/sysctl.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/memory_hotplug.h>
#include <linux/nodemask.h>
#include <linux/vmalloc.h>
#include <linux/vmstat.h>
#include <linux/mempolicy.h>
#include <linux/stop_machine.h>
#include <linux/sort.h>
#include <linux/pfn.h>
#include <linux/backing-dev.h>
#include <linux/fault-inject.h>
#include <linux/page-isolation.h>
#include <linux/debugobjects.h>
#include <linux/kmemleak.h>
#include <linux/compaction.h>
#include <trace/events/kmem.h>
#include <linux/memcontrol.h>
#include <linux/prefetch.h>
#include <linux/mm_inline.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/sched/rt.h>
#include <linux/kvm_host.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include "drivers/virtio/virtio_pci_common.h"  /* don't do relative path */
#include <net/ip.h>
#include <linux/platform_device.h>
#include <linux/serial_8250.h>
#include <asm/serial.h>
#include <kvm/iodev.h>
#include <scsi/scsi_host.h>
#include "kernel/sched/sched.h"            /* don't do relative path */
#include "drivers/tty/serial/8250/8250.h"  /* don't do relative path */
#include "drivers/vhost/vhost.h"           /* don't do relative path */
#include "arch/x86/kvm/lapic.h"            /* don't do relative path */
#include "block/blk-mq.h"                  /* don't do relative path */
#include "block/blk-mq-tag.h"              /* don't do relative path */
#include "block/blk-wbt.h"                 /* don't do relative path */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
#include <asm/text-patching.h>
#endif

#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/div64.h>
#include <asm/hypervisor.h>

#include "kdbxdefs.h"
#include "kdbxproto.h"
#include "kdbx_linux.h"
#include "kdbx_ept.h"

#endif /* !_KDBINC_H */
