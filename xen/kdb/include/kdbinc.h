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

#ifndef _KDBINC_H
#define _KDBINC_H

#include <xen/compile.h>
#include <xen/config.h>
#include <xen/version.h>
#include <xen/compat.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/mm.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/console.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <xen/rangeset.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/delay.h>
#include <xen/shutdown.h>
#include <xen/percpu.h>
#include <xen/multicall.h>
#include <xen/rcupdate.h>
#include <xen/ctype.h>
#include <xen/symbols.h>
#include <xen/shutdown.h>
#include <xen/serial.h>
#if XEN_VERSION == 4 && XEN_SUBVERSION > 1 
#include <xen/watchdog.h>
#endif
#include <xen/grant_table.h>
#include <xen/iommu.h>
#include <asm/debugger.h>
#include <asm/shared.h>
#include <asm/apicdef.h>
#include <asm/hvm/iommu.h>

#include <asm/nmi.h>
#include <asm/p2m.h>
#include <asm/debugreg.h>
#include <public/sched.h>
#include <public/vcpu.h>
#ifdef _XEN_LATEST
#include <xsm/xsm.h>
#endif

#include <asm/hvm/vmx/vmx.h>

#include "kdb_extern.h"
#include "kdbdefs.h"
#include "kdbproto.h"

#endif /* !_KDBINC_H */
