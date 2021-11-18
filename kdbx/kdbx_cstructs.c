#include "include/kdbxinc.h"

/* 
 * Copyright (C) 2009, 2020 Mukesh Rathor. All rights reserved.
 * 
 * 1. Build module.ko with full symbols (-g).
 * 2. Use pahole utility to generate a text file containing all structs:
 *      pahole --suppress_force_paddings --suppress_aligned_attribute \
 *             --suppress_packed module.ko > pahole.cstructs
 * 3. Now convert the text file to elf using:
 *      objcopy --input binary --output elf64-x86-64 pahole.cstructs \
 *              -B i386 pahole.o
 * 4. kdbx/Makefile : will then link pahole.o
 */

extern u64 _binary_pahole_cstructs_start;
static char *csttext;           /* big text of c structs */

int kdbx_test_cstruct=1;        /* just to test */

struct kdbx_testst {  
    unsigned int   foo;
    void *         tmpptr;
    struct abc * * abcp;
    clockid_t      clockid;
    void           (*probe_roms)(int, long);
    char           name[56];

    union {  
        ulong     testu;
        union {};
    };
    void           (*fptr8)(void);
    unsigned int field1:1;
    unsigned int field2:2;
    unsigned int field3:1;

    /* Force alignment to the next boundary: */
    unsigned :0;
                                                                             \
    unsigned int field9:1;
};
struct kdbx_testst kdbx_testst;

/* compile with -g, then run pahole and cut and paste here with backslashes
 * at the end */
char *kdbx_testst_str = "\
struct kdbx_testst { \
	unsigned int               foo;                  /*     0     4 */ \
 \
	/* XXX 4 bytes hole, try to pack */ \
 \
	void *                     tmpptr;               /*     8     8 */ \
	struct abc * *             abcp;                 /*    16     8 */ \
	clockid_t                  clockid;              /*    24     4 */ \
 \
	/* XXX 4 bytes hole, try to pack */ \
 \
	void                       (*probe_roms)(int, long int); /*    32     8 */ \
	char                       name[56];             /*    40    56 */ \
	/* --- cacheline 1 boundary (64 bytes) was 32 bytes ago --- */ \
	union { \
		ulong              testu;                /*    96     8 */ \
		union { \
		};                                       /*    96     0 */ \
	};                                               /*    96     8 */ \
	void                       (*fptr8)(void);       /*   104     8 */ \
	unsigned int               field1:1;             /*   112: 0  4 */ \
	unsigned int               field2:2;             /*   112: 1  4 */ \
	unsigned int               field3:1;             /*   112: 3  4 */ \
 \
	/* XXX 28 bits hole, try to pack */ \
 \
	/* Force alignment to the next boundary: */ \
	unsigned int               :0; \
 \
	unsigned int               field9:1;             /*   116: 0  4 */ \
 \
	/* size: 120, cachelines: 2, members: 12 */ \
	/* sum members: 104, holes: 2, sum holes: 8 */ \
      /* sum bitfield members: 5 bits, bit holes: 1, sum bit holes: 28 bits */ \
	/* bit_padding: 31 bits */ \
	/* last cacheline: 56 bytes */ \
}; \
";


void kdbx_init_teststruct(void)
{
    struct kdbx_testst *p = &kdbx_testst;

    p->foo = 0x987;
    p->tmpptr = (void *)0xbeefdeadbeef;
    p->abcp = (void *)0xabcdef1234567;
    p->probe_roms = (void *)0xffffffff8376dba8;
    strcpy(p->name, "Hello there");
    p->fptr8 = (void *)0x87654321;            /* should print leading 8 zeros */
    p->field1 = 1;
    p->field2 = 0x3;
    p->field3 = 0;
    p->field9 = 1;
}


#define MAX_STRUCT_NAME_LEN  256
static char cstnmbuf[MAX_STRUCT_NAME_LEN] = {[0] = ' '};  /* temp buf */

#if 0
/* EXAMPLE C STRUCT in cstruct.out:  
 * Types keywords: unsigned int, int, short int, u32, short unsigned int,
 *   const long unsigned int long unsigned int, long int, volatile long int, u64
 *   char, unsigned char, const char *, 
 *   void *, struct abc *, struct abc * *, const struct abc *,
 */
struct xyz {
    unsigned int   foo;         /* 0   4 */       : offset and size
    void *         tmpptr;      /* 4   8 */
    struct abc * * abcp;        /* 12  8 */
    clockid_t      clockid;     /* 20  4 */
    void           (*probe_roms)(abc, xyz, ...);  /*     24     8 */
    char           name[56];    /* 32  56 */

    union {
        union ....
    }
    unsigned int field1:1;      /*  2236: 0  4 */
    unsigned int field2:2;      /*  2236: 1  4 */
    unsigned int field3:1;      /*  2236: 3  4 */

    /* Force alignment to the next boundary: */
    unsigned :0;      

    unsigned int field9:1;      /*  2240: 0  4 */
    ...
}

char *ckeywords = "short int long u32 u64 signed unsigned const volatile "
                    "enum char void struct";
#endif


static int kdbx_dec_digit(char c)
{
    return (c >= '0' && c <= '9');
}

/* strp points to ascii "??342??", extract that value where ? could be space
 * or ':' or newline etc... This to extract offset and size in the comment
 * line of the cstruct text. They are in decimal. */
static noinline char *kdbx_extract_numeric(char *strp, int *val)
{
    int intval=0;

    if (strp == NULL || *strp == '\0')
        return NULL;

    for (; *strp && !kdbx_dec_digit(*strp); strp++);
    if (*strp == '\0')
        return NULL;

    for (; *strp && kdbx_dec_digit(*strp); strp++) {
        intval = (intval * 10) + (*strp - '0');
    }
    *val = intval;
    return strp;
}

/* offs: starting bit number. Thus, offs=3, numbits=4, then print 4 bits
 *       starting at bit number 3 in the u64 value */
static noinline void kdbx_print_bitfield(ulong ulval, int numbits, int offs)
{
    int i;
    ulong hexval=0, mask=0;

    ulval = ulval >> offs;
    for(i=0; i < numbits; i++)
        mask = (mask << 1) | 1;
    ulval = ulval & mask;
    kdbxp("%lx", ulval);
}

/* strp pointing to ';' in 'int foo; \/\* offs sz \*\/' */
static noinline char *kdbx_print_field_val(char *strp, char *addr, int bf_numbits)
{
    char *p;
    unsigned char ucharval;
    unsigned short ushortval;
    unsigned int uintval;
    unsigned long ulongval;
    int i, bfoffs=-1, offset=-1, size=-1;

    /* Normal field: '2224 8' 
     * bit field:  '2240: 1  4' OR '2255:27 8' */

    strp = kdbx_extract_numeric(strp, &offset);
    if (strp && *strp == ':') {
        strp = kdbx_extract_numeric(strp, &bfoffs);
    }

    strp = kdbx_extract_numeric(strp, &size);
    if (strp == NULL || offset == -1 || size == -1) {
        kdbxp("Bummer: strp:%px offset:%d size:%d bfnumb:%d\n", strp, offset,
              size, bf_numbits);
        return NULL;
    }

    if (bf_numbits && bfoffs < 0) {
        kdbxp("Bummer: bf_numbits:%d  bfoffs:%d\n", bf_numbits, bfoffs);
        return NULL;
    }

    p = addr + offset;
    KDBGP("prntfldval: p:%px offs:%d sz:%d bfoffs:%d bf_numbits:%d\n", p, 
          offset, size, bfoffs, bf_numbits);

    switch (size) {
        case 1:
            ucharval = *((unsigned char *)p);
            if (bf_numbits)
                kdbx_print_bitfield((ulong)ucharval, bf_numbits, bfoffs);
            else
                kdbxp("%x", ucharval);
            break;

        case 2:
            ushortval = *((unsigned short *)p);
            if (bf_numbits)
                kdbx_print_bitfield((ulong)ushortval, bf_numbits, bfoffs);
            else
                kdbxp("%x", ushortval);
            break;

        case 4:
            uintval = *((unsigned int *)p);
            if (bf_numbits)
                kdbx_print_bitfield((ulong)uintval, bf_numbits, bfoffs);
            else
                kdbxp("%x", uintval);
            break;

        case 8:
            ulongval = *((unsigned long *)p);
            if (bf_numbits)
                kdbx_print_bitfield((ulong)ulongval, bf_numbits, bfoffs);
            else
                kdbxp("%lx", ulongval);
            break;

        default:
            if (size <= 0) {
                kdbxp("Bummer: invalid size:%d\n", size);
                return NULL;
            }
            if (size < 32) {
                for (i=0; i < 32; i++, p++)
                    kdbxp("%x", *p);
                kdbxp("\n");
            } else {
                kdbxp("Array longer than 32 of sz:%d at:%px", size, p);
            }
    }

    /* go past the comment end */
    if (*strp != '/')
        for (; *strp && *strp != '/'; strp++);
    strp++;
    
    return strp;
}

/* 
 * strp: pointing to ';' in "unsigned int foo; .. " 
 * addr: beginning addr user gave for struct
 */
static noinline char *kdbx_print_field(char *strp, char *addr)
{
    int bf_numbits=0;
    char *tmp, *p = strp;

    KDBGP("prntfld: strp:%px addr:%px\n", strp, addr);

    /* strp pointing to ';' in :
     *     unsigned int foo;
     *     void  (*fptr1)(int, long int);
     *     void  (*fptr)(void);
     *     usigned int field1:1
     */
    /* go back looking for space to find field name "foo" or "fptr" */
    p--;
    if (*p == ')') {           /* function ptr */
        for (; p > csttext && *p != '('; p--);   /* parameter paren */
        p--;
        for (; p > csttext && *p != '('; p--);   /* function name  paren */
    } else {                  /* non function ptr field */
        for (; p > csttext && *p != ' '; p--);
        p++;
    }
    if (p == NULL || *p == '\0' || p == csttext || p == csttext+1) {
        KDBGP("prntfld: p:%px\n", p);
        return NULL;
    }
    
    if (*p == ':')
        return strp+1;      /* 'unsigned int :0;' : forces alignment, skip */

    if (*p == '(') {   /* 'void  (*funcptr)(xyz, abc); ....' */
        p++;           /* print the '*' in above */
        tmp = strchr(p, ')');
    } else {
        for (tmp=p; tmp < strp; tmp++) {
            if (*tmp == ':') {
                strp = kdbx_extract_numeric(tmp, &bf_numbits);
                if (bf_numbits > 64) {
                    kdbxp("Bummer: invalid bf_numbits:%d\n", bf_numbits);
                    return NULL;
                }
            }
        }
        tmp = strp;         /* print bitfield with number of bits */
    }

    /* finally, yay, print field name and then value */
    kdbxp("%.*s: ", tmp-p, p);
    strp = kdbx_print_field_val(strp, addr, bf_numbits);
    KDBGP("prntfld: return strp:%px\n", strp);
    return strp;
}

/* strp pointing to '{' in 'enum {' or 'union {' */
static noinline char *kdbx_print_union(char *strp, char *addr)
{
    int curlyb = 1;

    if (*strp != '{') {
        kdbxp("prntunion: strp %px not at strtcurly, at:%x\n", strp, *strp);
        return NULL;
    }

    /* for now, just skip unions */
    kdbxp("Fixme: skipping union/enums ... \n");
    for (strp++;curlyb; strp++) {
        if (*strp == '{')
            curlyb++;      /* embedded unions/enums */
        else if (*strp == '}')
            curlyb--;
    }
    /* go past '};' : pahole never puts a space in between them */
    strp += 2;

    KDBGP("prntunion: return strp:%px\n", strp);
    return strp;
}

/* strategy: simple, each line has terminating semicolon before comment with
 *           offset and size, then walk back to prev space which gives the
 *           field name. (Bit fields and unions a bit of extra work).
 * PreCondition: strp pointing to '{' in 'struct xyz {\n'
 */
static noinline void kdbx_dump_fields(char *strp, char *addr)
{
    char *psav;
    int newline=0, curlyb=1;     /* curly brace count */

    KDBGP("dumpflds: strp:%px addr:%px\n", strp, addr);
    psav = ++strp;      /* go past "struct xyz {" */

    while (strp && *strp && curlyb) {
        strp = strpbrk(strp, ";{/}");  /* look for one of ';' '{' '/' ... */
        if (strp == NULL) {
            kdbxp("Unexpected end of text...\n");
            return;
        }
        if (*strp == '/') {
            for (strp++; *strp && *strp != '/'; strp++);
            strp++;
            continue;
        }
        if (*strp == '\0') {
            kdbxp("Unexpected end of text nullcha...\n");
            return;
        }

        if (*strp == ';')
            strp = kdbx_print_field(strp, addr);
        else if (*strp == '{')
            strp = kdbx_print_union(strp, addr);
        else if (*strp == '}')
            curlyb--;
        
        /* two fields per line */
        if (newline) {
            kdbxp("\n");
            newline = 0;
        } else {
            kdbxp("\t");
            newline = 1;
        }
    }
    
}

/* search for struct name "xyz" and return ptr to "{" after it, or NULL */
static noinline char *kdbx_find_cstruct(char *name)
{
    char *strp;
    int len=strlen(name);

    if (len > MAX_STRUCT_NAME_LEN - 3) {
        kdbxp("struct name len %d too big\n", len);
        return NULL;
    }

    /* already has space at 0, add space after and do strstr */
    strncpy(cstnmbuf+1, name, MAX_STRUCT_NAME_LEN-1);
    cstnmbuf[1+len] = ' '; 
    cstnmbuf[1+len+1] = '\0'; 

    strp = strstr(csttext, name);
    if (strp == NULL) {
        kdbxp("struct name %s not found\n", name);
        return NULL;
    }

    for (; *strp && *strp != '{'; strp++);
    return *strp == '{' ? strp : NULL;
}

/* User thinks "struct xyz ....", starts at addr. With name pointing to "xyz",
 * try to dump the entire struct */
void kdbx_print_cstruct(char *name, char *addr)
{
    // char *stname = strim(name);   /* remove leading/trailing spaces */
    char *stname = name;
    char *q;                    /* ptr to struct layout text */

    /* just use kdbx_handle_sysrq_c() to debug */
    if (kdbx_test_cstruct) {
        kdbx_init_teststruct();
        csttext = kdbx_testst_str;
        addr = (char *)&kdbx_testst;
        kdbxp("kdbx_testst_str: %px csttxt:%px addr:%px\n", kdbx_testst_str,
              csttext, addr);
    } else {
        csttext = (char *)&_binary_pahole_cstructs_start;
    }
    kdbxp("print_cstruct: csttext is: %px\n", csttext);

    q = kdbx_find_cstruct(stname);
    if (q == NULL)
        return;

    /* q now points to the '{' after "xyz" in "struct xyz {\n" */
    kdbx_dump_fields(q, addr);
}
