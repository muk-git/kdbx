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

/* information for symbols for a guest (includeing dom 0 ) is saved here */
struct gst_syminfo {           /* guest symbols info */
    pid_t gpid;                /* guest pid */
    int   bitness;             /* 32 or 64 */
    void *addrtblp;            /* ptr to (32/64)addresses tbl */
    u8   *toktbl;              /* ptr to kallsyms_token_table */
    u16  *tokidxtbl;           /* ptr to kallsyms_token_index */
    u8   *kallsyms_names;      /* ptr to kallsyms_names */
    long  kallsyms_num_syms;   /* number of symbols */
    kdbva_t  stext;            /* value of _stext in guest */
    kdbva_t  etext;            /* value of _etext in guest */
    kdbva_t  sinittext;        /* value of _sinittext in guest */
    kdbva_t  einittext;        /* value of _einittext in guest */
};

#define MAX_CACHE 16                              /* cache upto 16 guests */
struct gst_syminfo gst_syminfoa[MAX_CACHE];       /* guest symbol info array */

static struct gst_syminfo *kdb_get_syminfo_slot(void)
{
    int i;

    for (i=0; i < MAX_CACHE; i++)
        if (gst_syminfoa[i].addrtblp == NULL)
            return (&gst_syminfoa[i]);      

    return NULL;
}

static struct gst_syminfo *kdb_gpid2syminfop(pid_t gpid)
{
    int i;

    for (i=0; i < MAX_CACHE; i++)
        if ( kdb_pid2tgid(gst_syminfoa[i].gpid) == kdb_pid2tgid(gpid) )
            return (&gst_syminfoa[i]);      

    return NULL;
}

int kdb_guest_sym_loaded(pid_t gpid)
{
    return kdb_gpid2syminfop(gpid) ? 1 : 0;
}

/* check if an address looks like text address in guest */
int kdb_is_addr_guest_text(kdbva_t addr, pid_t gpid)
{
    struct gst_syminfo *gp = kdb_gpid2syminfop(gpid);

    if (!gp || !gp->stext || !gp->etext)
        return 0;

    KDBGP1("guestaddr: addr:%lx gpid:%d\n", addr, gpid);

    return ( (addr >= gp->stext && addr <= gp->etext) ||
             (addr >= gp->sinittext && addr <= gp->einittext) );
}

/* returns: value of kallsyms_addresses[idx] */
static kdbva_t kdb_rd_guest_addrtbl(struct gst_syminfo *gp, int idx)
{
    kdbva_t addr, retaddr=0;
    int num = gp->bitness/8;       /* whether 4 byte or 8 byte ptrs */
    pid_t gpid = gp->gpid;
    struct kvm_vcpu *vp = kdb_pid_to_vcpu(gpid, 0);

    addr = (kdbva_t)(((char *)gp->addrtblp) + idx * num);
    KDBGP1("rdguestaddrtbl:addr:%lx idx:%d\n", addr, idx);

    if (kdb_read_mem(addr, (kdbbyt_t *)&retaddr, num, vp) != num) {
        kdbxp("Can't read addrtbl gpid:%d at:%lx\n", gpid, addr);
        return 0;
    }
    KDBGP1("rdguestaddrtbl:exit:retaddr:%lx\n", retaddr);

    return retaddr;
}

/* Based on el5 kallsyms.c file. */
static unsigned int 
kdb_expand_el5_sym(struct gst_syminfo *gp, unsigned int off, char *result)
{   
    int len, skipped_first = 0;
    u8 u8idx, *tptr, *datap;
    pid_t gpid = gp->gpid;
    struct kvm_vcpu *vp = kdb_pid_to_vcpu(gpid, 0);

    *result = '\0';

    /* get the compressed symbol length from the first symbol byte */
    datap = gp->kallsyms_names + off;
    len = 0;
    if ((kdb_read_mem((kdbva_t)datap, (kdbbyt_t *)&len, 1, vp)) != 1) {
        KDBGP("failed to read guest memory\n");
        return 0;
    }
    datap++;

    /* update the offset to return the offset for the next symbol on
     * the compressed stream */
    off += len + 1;

    /* for every byte on the compressed symbol data, copy the table
     * entry for that byte */
    while(len) {
        u16 u16idx, *u16p;
        if (kdb_read_mem((kdbva_t)datap, (kdbbyt_t *)&u8idx, 1, vp) != 1) {
            kdbxp("memory (u8idx) read error:%p\n",gp->tokidxtbl);
            return 0;
        }
        u16p = u8idx + gp->tokidxtbl;
        if (kdb_read_mem((kdbva_t)u16p, (kdbbyt_t *)&u16idx, 2, vp) != 2) {
            kdbxp("tokidxtbl read error:%p\n", u16p);
            return 0;
        }
        tptr = gp->toktbl + u16idx;
        datap++;
        len--;

        while ((kdb_read_mem((kdbva_t)tptr, (kdbbyt_t *)&u8idx, 1, vp)==1) &&
               u8idx) {

            if(skipped_first) {
                *result = u8idx;
                result++;
            } else
                skipped_first = 1;
            tptr++;
        }
    }
    *result = '\0';
    return off;          /* return to offset to the next symbol */
}

#define EL4_NMLEN 127
/* so much pain, so not sure of it's worth .. :).. */
static kdbva_t
kdb_expand_el4_sym(struct gst_syminfo *gp, int low, char *result, char *symp)
{   
    int i, j;
    kdbva_t addr;
    u8 *nmp = gp->kallsyms_names;       /* guest address space */
    kdbbyt_t byte, prefix;
    pid_t gpid = gp->gpid;
    struct kvm_vcpu *vp = kdb_pid_to_vcpu(gpid, 0);

    KDBGP1("Eel4sym:nmp:%p maxidx:$%d sym:%s\n", nmp, low, symp);
    for (i=0; i <= low; i++) {
        /* unsigned prefix = *name++; */
        if (kdb_read_mem((kdbva_t)nmp, &prefix, 1, vp) != 1) {
            kdbxp("failed to read:%p gpid:%x\n", nmp, gpid);
            return 0;
        }
        KDBGP2("el4:i:%d prefix:%x\n", i, prefix);
        nmp++;
        /* strncpy(namebuf + prefix, name, KSYM_NAME_LEN - prefix); */
        addr = (long)result + prefix;
        for (j=0; j < EL4_NMLEN-prefix; j++) {
            if (kdb_read_mem((kdbva_t)nmp, &byte, 1, vp) != 1) {
                kdbxp("failed read:%p gpid:%x\n", nmp, gpid);
                return 0;
            }
            KDBGP2("el4:j:%d byte:%x\n", j, byte);
            *(kdbbyt_t *)addr = byte;
            addr++; nmp++;
            if (byte == '\0')
                break;
        }
        KDBGP2("el4sym:i:%d res:%s\n", i, result);
        if (symp && strcmp(result, symp) == 0)
            return(kdb_rd_guest_addrtbl(gp, i));

        /* kallsyms.c: name += strlen(name) + 1; */
        if (j == EL4_NMLEN-prefix && byte != '\0')
            while (kdb_read_mem((kdbva_t)nmp, &byte, 1, vp) && byte != '\0')
                nmp++;
    }
    KDBGP1("Xel4sym: na-ga-da\n");
    return 0;
}

static uint kdb_get_el5_symoffset(struct gst_syminfo *gp, long pos)
{
    int i;
    u8 data, *namep;
    pid_t gpid = gp->gpid;
    struct kvm_vcpu *vp = kdb_pid_to_vcpu(gpid, 0);

    namep = gp->kallsyms_names;
    for (i=0; i < pos; i++) {
        if (kdb_read_mem((kdbva_t)namep, &data, 1, vp) != 1) {
            kdbxp("Can't read gpid:$%d mem:%p\n", gpid, namep);
            return 0;
        }
        namep = namep + data + 1;
    }
    return namep - gp->kallsyms_names;
}

/*
 * for a given guest gpid, convert addr to symbol. 
 * offset is set to  addr - symbolstart
 */
char *kdb_guest_addr2sym(unsigned long addr, pid_t gpid, ulong *offsp)
{
    static char namebuf[KSYM_NAME_LEN+1];
    unsigned long low, high, mid;
    struct gst_syminfo *gp = kdb_gpid2syminfop(gpid);

    *offsp = 0;
    if( !gp || gp->kallsyms_num_syms == 0 )
        return " ??? ";

    namebuf[0] = namebuf[KSYM_NAME_LEN] = '\0';

    /* do a binary search on the sorted kallsyms_addresses array */
    low = 0;
    high = gp->kallsyms_num_syms;

    while (high-low > 1) {
        mid = (low + high) / 2;
        if (kdb_rd_guest_addrtbl(gp, mid) <= addr) 
            low = mid;
        else 
            high = mid;
    }
    /* Grab name */
    if (gp->toktbl) {
        int symoff = kdb_get_el5_symoffset(gp,low);

        kdb_expand_el5_sym(gp, symoff, namebuf);
    } else
        kdb_expand_el4_sym(gp, low, namebuf, NULL);

    *offsp = addr - kdb_rd_guest_addrtbl(gp, low);

    return namebuf;
}


/* 
 * save guest (dom0 and others) symbols info : gpid and following addresses:
 *     &kallsyms_names &kallsyms_addresses &kallsyms_num_syms \
 *     &kallsyms_token_table &kallsyms_token_index
 */
void
kdb_sav_guest_syminfo(pid_t gpid, long namesp, long addrap, long nump,
                      long toktblp, long tokidxp)
{
    int bytes;
    long val = 0;    /* must be set to zero for 32 on 64 cases */
    struct gst_syminfo *gp = kdb_get_syminfo_slot();
    struct kvm_vcpu *vp = kdb_pid_to_vcpu(gpid, 0);

    if (gp == NULL) {
        kdbxp("kdb:kdb_sav_dom_syminfo():Table full.. symbols not saved\n");
        return;
    }
    memset(gp, 0, sizeof(*gp));

    gp->gpid = gpid;
    gp->bitness = kdb_guest_bitness(gpid);
    gp->addrtblp = (void *)addrap;
    gp->kallsyms_names = (u8 *)namesp;
    gp->toktbl = (u8 *)toktblp;
    gp->tokidxtbl = (u16 *)tokidxp;

    KDBGP("gpid:%d bitness:$%d numsyms:$%ld arrayp:%p\n", gpid,
          gp->bitness, gp->kallsyms_num_syms, gp->addrtblp);

    bytes = gp->bitness/8;
    if (kdb_read_mem(nump, (kdbbyt_t *)&val, bytes, vp) != bytes) {

        kdbxp("Unable to read number of symbols from:%lx\n", nump);
        memset(gp, 0, sizeof(*gp));
        return;
    } else
        kdbxp("Number of symbols:$%ld\n", val);

    gp->kallsyms_num_syms = val;

    bytes = (gp->bitness/8) * gp->kallsyms_num_syms;
    gp->stext = kdb_guest_sym2addr("_stext", gpid);
    gp->etext = kdb_guest_sym2addr("_etext", gpid);
    if (!gp->stext || !gp->etext)
        kdbxp("Warn: Can't find stext/etext\n");

    if (gp->toktbl && gp->tokidxtbl) {
        gp->sinittext = kdb_guest_sym2addr("_sinittext", gpid);
        gp->einittext = kdb_guest_sym2addr("_einittext", gpid);

        if (!gp->sinittext || !gp->einittext)
            kdbxp("Warn: Can't find sinittext/einittext\n");
    }
    KDBGP1("stxt:%lx etxt:%lx sitxt:%lx eitxt:%lx\n", gp->stext, gp->etext,
           gp->sinittext, gp->einittext);

    kdbxp("Succesfully saved symbol info\n");
}

/*
 * given a symbol string for a guest/gpid, return its address
 */
kdbva_t kdb_guest_sym2addr(char *symp, pid_t gpid)
{
    char namebuf[KSYM_NAME_LEN+1];
    int i, off=0;
    struct gst_syminfo *gp = kdb_gpid2syminfop(gpid);

    KDBGP1("sym2a: sym:%s gpid:%d numsyms:%ld\n", symp, gpid,
           gp ? gp->kallsyms_num_syms : -1);

    if (!gp)
        return 0;

    if (gp->toktbl == 0 || gp->tokidxtbl == 0)
        return(kdb_expand_el4_sym(gp, gp->kallsyms_num_syms, namebuf, symp));

    for (i=0; i < gp->kallsyms_num_syms; i++) {
        off = kdb_expand_el5_sym(gp, off, namebuf);
        KDBGP1("i:%d namebuf:%s\n", i, namebuf);

        if ( strcmp(namebuf, symp) == 0 )
            return kdb_rd_guest_addrtbl(gp, i);
    }
    KDBGP1("sym2a: exit: na-ga-da\n");

    return 0;
}
