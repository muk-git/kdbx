#ifndef __KDBX_EPT_H
#define __KDBX_EPT_H

#include "../../arch/x86/include/asm/vmx.h"

union kdbx_ept_entry {
    struct {
        u64 r       :   1,  /* bit 0 - Read permission */
        w           :   1,  /* bit 1 - Write permission */
        x           :   1,  /* bit 2 - Execute permission */
        emt         :   3,  /* bits 5:3 - EPT Memory type */
        ipat        :   1,  /* bit 6 - Ignore PAT memory type */
        sp          :   1,  /* bit 7 - Is this a superpage? */
        rsvd1       :   2,  /* bits 9:8 - Reserved for future use */
        recalc      :   1,  /* bit 10 - Software available 1 */
        snp         :   1,  /* bit 11 - VT-d snoop control in shared
                               EPT/VT-d usage */
        mfn         :   40, /* bits 51:12 - Machine physical frame number */
        sa_p2mt     :   6,  /* bits 57:52 - Software available 2 */
        access      :   4,  /* bits 61:58 - p2m_access_t */
        tm          :   1,  /* bit 62 - VT-d transient-mapping hint in
                               shared EPT/VT-d usage */
        avail3      :   1;  /* bit 63 - Software available 3 */
    };
    u64 epte;
};

typedef enum {
    ept_access_n     = 0,       /* No access permissions allowed */
    ept_access_r     = 1,       /* Read only */
    ept_access_w     = 2,       /* Write only */
    ept_access_rw    = 3,       /* Read & Write */
    ept_access_x     = 4,       /* Exec Only */
    ept_access_rx    = 5,       /* Read & Exec */
    ept_access_wx    = 6,       /* Write & Exec*/
    ept_access_all   = 7,       /* Full permissions */
} ept_access_t;

struct ept_data {
    union {
    struct {
            u64 ept_mt :3,
                ept_wl :3,
                rsvd   :6,
                asr    :52;
        };
        u64 eptp;
    };
    cpumask_var_t synced_mask;
};

#define is_epte_present(ept_entry)      ((ept_entry)->epte & 0x7)
#define is_epte_superpage(ept_entry)    ((ept_entry)->sp)

#define ept_get_wl(ept)   ((ept)->ept_wl)
#define ept_get_asr(ept)  ((ept)->asr)
#define ept_get_eptp(ept) ((ept)->eptp)
#define ept_get_synced_mask(ept) ((ept)->synced_mask)

#define EPT_TABLE_ORDER         9
#define EPTE_SUPER_PAGE_MASK    0x80
#define EPTE_MFN_MASK           0xffffffffff000ULL
#define EPTE_AVAIL1_MASK        0xF00
#define EPTE_EMT_MASK           0x38
#define EPTE_IGMT_MASK          0x40
#define EPTE_AVAIL1_SHIFT       8
#define EPTE_EMT_SHIFT          3
#define EPTE_IGMT_SHIFT         6
#define EPTE_RWX_MASK           0x7
#define EPTE_FLAG_MASK          0x7f

#define EPT_EMT_UC              0
#define EPT_EMT_WC              1
#define EPT_EMT_RSV0            2
#define EPT_EMT_RSV1            3
#define EPT_EMT_WT              4
#define EPT_EMT_WP              5
#define EPT_EMT_WB              6
#define EPT_EMT_RSV2            7

extern int get_ept_level(struct kvm_vcpu *vcpu);

#endif
