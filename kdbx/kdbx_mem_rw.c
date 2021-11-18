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

/*
 * copy/read machine memory. 
 * RETURNS: number of bytes copied 
 */
int kdbx_read_mmem(kdbma_t maddr, kdbbyt_t *dbuf, int len)
{
    ulong orig = len;

    if ((maddr >> PAGE_SHIFT) > max_pfn) {
        kdbxp("pfn: %lx is larger than max_pfn\n", maddr>>PAGE_SHIFT);
        return 0;
    }

    while (len > 0) {
        ulong pagecnt = min_t(long, PAGE_SIZE - (maddr & ~PAGE_MASK), len);
        char *va = phys_to_virt(maddr); /* no kmap(), it calls _cond_resched */

        if ( va == NULL ) {
            kdbxp("kdbx: unable to map: %016lx. va:%px\n", maddr, va);
            break;
        }

        va = va + (maddr & (PAGE_SIZE-1));        /* add page offset */
        memcpy(dbuf, (void *)va, pagecnt);

        KDBGP1("maddr:%lx va:%px len:%x pagecnt:%x\n", maddr, va, len, pagecnt);

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
    char *va;
    ulong rval;
    ulong pfn = kdbx_p2m(vp, gfn, 1);
    struct page *pg = pfn_valid(pfn) ? pfn_to_page(pfn) : NULL;

    va = pg ? page_to_virt(pg):NULL;  /* don't kmap(), it calls _cond_resched */

    KDBGP1("lookup e: gfn:%lx pfn:%lx idx:%x va:%px\n", gfn, pfn, idx, va);
    if ( !pfn_valid(pfn) ) {
        kdbxp("kdb_lookup_pt_entry: pfn:%lx invalid. gfn:%lx vp:%px\n", pfn,
              gfn, vp);
        return 0;
    }

    if ( pg == NULL || va == NULL ) {
        kdbxp("lookup: Unable to map pfn: %lx pg:%px\n", pfn, pg);
        return 0;
    }

    va += idx * 8;
    rval = *(ulong *)va;
    KDBGP1("lookup e: return entry:%lx\n", rval);

    return rval;
}

/* given a cr3 gfn, walk the entire pt pointed for the addr, and 
 * return pfn/mfn for the provided addr */
static ulong kdb_pt_pfn(ulong addr, ulong cr3gfn, struct kvm_vcpu *vp, 
                        int *levelp)
{
    ulong pa, gfn, entry, offs;

    *levelp = PG_LEVEL_NONE;

    KDBGP1("ptepfn: addr:%lx cr3gfn:%lx vp:%px\n", addr, cr3gfn, vp);
    entry = kdb_lookup_pt_entry(cr3gfn, pgd_index(addr), vp);
    if ( entry == 0 ) {
        kdbxp("pgd not present. cr3gfn:%lx pgdidx:%x vp:%px\n",
              cr3gfn, pgd_index(addr), vp);

        return (ulong)-1;
    }

    *levelp = PG_LEVEL_1G;
    gfn = pud_pfn( (pud_t){.pud = entry} );        /* L3 Page */
    entry = kdb_lookup_pt_entry(gfn, pud_index(addr), vp);
    if ( entry == 0 || !pud_present((pud_t){.pud = entry}) ) {
        kdbxp("pud is not present. entry:%lx\n", entry);
        return (ulong)-1;
    }
    if ( pud_large((pud_t){.pud = entry}) ) {
        gfn = pud_pfn( (pud_t){.pud = entry} );
        offs = addr & ~PUD_PAGE_MASK;
        pa = (gfn << PAGE_SHIFT ) | offs;
        gfn = pa >> PAGE_SHIFT;
        goto out;
    }

    *levelp = PG_LEVEL_2M;
    // gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    gfn = pmd_pfn( (pmd_t){.pmd = entry} );        /* L2 Page */
    entry = kdb_lookup_pt_entry(gfn, pmd_index(addr), vp);
    if ( entry == 0 || !pmd_present((pmd_t){.pmd = entry}) ) {
        kdbxp("pmd is not present. entry:%lx\n", entry);
        return (ulong)-1;
    }
    if ( pmd_large((pmd_t){.pmd = entry}) ) {
        gfn = pmd_pfn( (pmd_t){.pmd = entry} );
        offs = addr & ~PMD_PAGE_MASK;
        pa = (gfn << PAGE_SHIFT ) | offs;
        gfn = pa >> PAGE_SHIFT;
        goto out;
    }

    *levelp = PG_LEVEL_4K;
    gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    entry = kdb_lookup_pt_entry(gfn, pte_index(addr), vp);
    if ( entry == 0 || !pte_present((pte_t){.pte = entry}) ) {
        kdbxp("pte is not present. entry:%lx\n", entry);
        return (ulong)-1;
    }
    gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;

out:
    KDBGP1("kdb_pt_pfn: addr: %lx gfn:%lx level:%d\n", addr, gfn, *levelp);
    return kdbx_p2m(vp, gfn, 1);
}

/* RETURNS: number of bytes copied */
static int kdb_rw_cr3_mem(kdbva_t addr, kdbbyt_t *buf, int len,
                          struct kvm_vcpu *vp, int toaddr)
{
    ulong cr3gfn;
    int level, orig_len = len;

    if ( vp ) {
        cr3gfn = kdbx_get_hvm_field(vp, GUEST_CR3) >> PAGE_SHIFT;
    } else {
        // cr3gfn = (__pa(init_mm.pgd->pgd)) >> PAGE_SHIFT;
        kdbxp("kdb_rw_cr3_mem: guest only, vp must be specified.\n");
        return 0;
    }

    KDBGP1("rw-cr3mem: addr:%lx vp:%px len:%d to:%d cr3gfn:%lx\n", addr, vp, 
           len, toaddr, cr3gfn);

    while (len > 0) {
        char *va;
        ulong pagecnt = min_t(long, PAGE_SIZE - (addr & ~PAGE_MASK), len);
        ulong pfn = kdb_pt_pfn(addr, cr3gfn, vp, &level);  /* pfn is mfn */
        struct page *pg = pfn ? (pfn_valid(pfn) ? pfn_to_page(pfn) : NULL):NULL;

        /* don't kmap(), it calls _cond_resched */
        va = pg ? page_to_virt(pg) : NULL;  

        if ( pfn == 0 || !pfn_valid(pfn) ) {
            kdbxp("kdb_rw_cr3_mem: addr:%lx len:%d. pfn:%lx invalid\n", 
                  addr, len, pfn);
            break;
        }
        if ( pg == NULL || va == NULL ) {
            kdbxp("kdbx: unable to map addr:%016lx pfn:%lx\n", addr, pfn);
            break;
        }

        va = va + (addr & (PAGE_SIZE - 1));           /* add page offset */
#if 0
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
#endif
        if ( toaddr )
            memcpy(va, buf, pagecnt);
        else
            memcpy(buf, va, pagecnt);

        KDBGP1("addr:%lx va:%px len:%x pagecnt:%x\n", addr, va, len, pagecnt );

        len = len  - pagecnt;
        addr += pagecnt;
        buf += pagecnt;
    }

    return orig_len - len;
}

/*
 * copy/read host or guest memory
 * RETURNS: number of bytes copied 
 */
int kdbx_read_mem(kdbva_t saddr, kdbbyt_t *dbuf, int len, struct kvm_vcpu *vp)
{
    KDBGP2("read mem: saddr:%lx (int)src:%x len:%d vp:%px\n", saddr,
           *(uint *)dbuf, len, vp);

    if ( max_pfn_mapped == 0 )
        return kdb_early_rmem(saddr, dbuf, len);

    if ( vp )
        return kdb_rw_cr3_mem(saddr, dbuf, len, vp, 0);

    if (saddr < 0xffff800000000000) {             /* is user space address */
        len -= copy_from_user(dbuf, (void *)saddr, len);
    } else {
        /* saddr must be the host va, so just access it directly. In case of
         * exception, will back to cmd input after printing exception msg and
         * caller will not be accessing the dbuf */
        memcpy(dbuf, (void *)saddr, len);
#if 0
        ret = probe_kernel_read((void *)dbuf, (void *)saddr, len);
        if ( ret ) {
            KDBGP1("probe_kernel failed: saddr:%lx ret:%ld\n", saddr, ret);
            return 0;
        }
#endif
    }
    KDBGP("kdbx_read_mem: saddr:%lx ret len:%ld\n", saddr, len);
    return len;
}

/*
 * kernel text is protected, so can't use probe_kernel_write.
 * RETURNS: number of bytes written
 */
static int kdbx_write_protected(kdbva_t daddr, kdbbyt_t *sbuf, int len )
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
extern bool acpi_permanent_mmap;
int kdbx_write_mem(kdbva_t daddr, kdbbyt_t *sbuf, int len, struct kvm_vcpu *vp)
{
    ulong rc;

    KDBGP2("write mem: addr:%lx (int)src:%lx len:%d vp:%px\n", daddr,
           *(uint *)sbuf, len, vp);

    /* if we are early during boot before init_mem_mapping(). 
     * nb: if ( max_pfn_mapped == 0 ): can't use this anymore in newer kernels
     * so, acpi_permanent_mmap appears to be a good global to pick */
    if (acpi_permanent_mmap == false)
        return kdb_early_wmem(daddr, sbuf, len);

    if ( vp == NULL ) {          /* host memory */
        if ( __kernel_text_address(daddr) )
            // return kdb_early_wmem(daddr, sbuf, len);
            /* earlier in boot in setup_arch, following not work in 4.14.35 */
            return kdbx_write_protected(daddr, sbuf, len);

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

static int kdbx_wpt_1G_page(ulong entry, ulong addr)
{
    char buf[32];
    ulong pa, gfn, offs = addr & ~PUD_PAGE_MASK;

    kdbxp("l3/pud %lx points to 1G page. offs in 1G page: %lx\n", entry, offs);
    gfn = pud_pfn( (pud_t){.pud = entry} );
    pa = (gfn << PAGE_SHIFT) | offs; /* gfn already shifted left by 18 bits */

    KDBGP1("1G page: gfn:%lx pa:%lx\n", gfn, pa);
    if (kdbx_read_mmem(pa, buf, 16) == 0) {
        kdbxp("Failed to read 16 bytes at maddr: %lx\n", pa);
        return -EINVAL;
    }
    kdbxp("%016lx: %016lx %016lx\n", pa, *(ulong *)buf, *(((ulong *)buf)+1));
    return 0;
}

static int kdbx_wpt_2M_page(ulong entry, ulong addr)
{
    char buf[32];
    ulong pa, gfn, offs = addr & ~PMD_PAGE_MASK;

    kdbxp("l3/pmd %lx points to 2M page. offs in 2M page: %lx\n", entry, offs);
    gfn = pmd_pfn( (pmd_t){.pmd = entry} );
    pa = (gfn << PAGE_SHIFT) | offs; /* gfn already shifted left by 9 bits */

    KDBGP1("2M page: gfn:%lx pa:%lx\n", gfn, pa);
    if (kdbx_read_mmem(pa, buf, 16) == 0) {
        kdbxp("Failed to read 16 bytes at maddr: %lx\n", pa);
        return -EINVAL;
    }
    kdbxp("%016lx: %016lx %016lx\n", pa, *(ulong *)buf, *(((ulong *)buf)+1));
    return 0;
}

/* see also: fault.c:dump_pagetable() and pageattr.c:lookup_address()
 * RETURN: 0 on succes. -error if error */
int kdbx_walk_pt(ulong addr, ulong cr3gfn, struct kvm_vcpu *vp)
{
    char buf[32];
    int offs, idx;
    ulong pa, gfn, entry;   /* gfn is pfn/mfn if host */

    /* cr3gfn is pfn/mfn if host, ie vp==0 */
    if (cr3gfn == 0) {
        if ( vp )
            cr3gfn = kdbx_get_hvm_field(vp, GUEST_CR3) >> PAGE_SHIFT;
        else
            cr3gfn = (__pa(init_mm.pgd)) >> PAGE_SHIFT;
    }
    if ( !pfn_valid(cr3gfn) ) {
        kdbxp("cr3gfn is invalid:%lx vp:%px\n", cr3gfn, vp);
        return -EINVAL;
    }

    idx = pgd_index(addr);
    entry = kdb_lookup_pt_entry(cr3gfn, idx, vp);  /* cr3 == L4 page */
    kdbxp("cr3gfn: %lx l4idx: %x l4[%x]:%lx\n", cr3gfn, idx, idx, entry);
    if ( entry == 0 )
        return -EINVAL;

    // gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    gfn = pud_pfn( (pud_t){.pud = entry} );        /* L3 Page */
    idx = pud_index(addr);
    entry = kdb_lookup_pt_entry(gfn, idx, vp); /* on host: entry=*(gfn+idx) */
    kdbxp("l3page: %lx l3idx: %x l3[%x]:%lx\n", gfn, idx, idx, entry);
    if ( entry == 0 || !pud_present((pud_t){.pud = entry}) ) 
        return -EINVAL;

    if ( pud_large((pud_t){.pud = entry}) )
        return kdbx_wpt_1G_page(entry, addr);

    // gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;
    gfn = pmd_pfn( (pmd_t){.pmd = entry} );        /* L2 Page */
    idx = pmd_index(addr);
    entry = kdb_lookup_pt_entry(gfn, idx, vp);
    kdbxp("l2page: %lx l2idx: %x l2[%x]:%lx\n", gfn, idx, idx, entry);
    if ( entry == 0 || !pmd_present((pmd_t){.pmd = entry}) ) 
        return -EINVAL;

    if ( pmd_large((pmd_t){.pmd = entry}) )
        return kdbx_wpt_2M_page(entry, addr);

    gfn = (entry & PTE_PFN_MASK) >> PAGE_SHIFT;   /* L1 page */
    idx = pte_index(addr);
    entry = kdb_lookup_pt_entry(gfn, idx, vp);
    kdbxp("l1page: %lx l1idx: %x l1[%x]:%lx\n", gfn, idx, idx, entry);
    if ( entry == 0 || !pte_present((pte_t){.pte = entry}) ) 
        return -EINVAL;

    offs = addr & ~PAGE_MASK;
    pa = (pte_pfn((pte_t){.pte = entry}) << PAGE_SHIFT) | offs;
    KDBGP1("4K page: pa:%lx offs:%x\n", pa, offs);
    if (kdbx_read_mmem(pa, buf, 16) == 0) {
        kdbxp("Failed to read 16 bytes at maddr: %lx\n", pa);
        return -EINVAL;
    }
    return 0;
}
