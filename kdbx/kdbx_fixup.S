#include <linux/linkage.h>
#include <asm/alternative-asm.h>
#include <asm/export.h>
#include <asm/frame.h>

# parameters(rdi == argc, rsi == argv, rdx == regs, rcx == fp to call);
#   need to call: rc = fp(argc, argv, regs)
#                 return rc;
#
# non-volatile: r12, r13, r14, r15, rbx, rsp, rbp
#     volatile: rax, rcx, rsi, rdi, r8, r9, r10, r11
# Notes: we need to only save the non-volatile across the call. Also, we 
#        disable interrupts to avoid exception in irq path.
#
ENTRY(kdbx_call_cmd_func)
    FRAME_BEGIN       # see Documentation/stack-validation.txt
    pushq %rbx
    pushf        # push eflags
    cli          # disable

    movq kdbx_excp_ptr(%rip), %rbx
    movq $excp_res_label, 0x0(%rbx) # excp->resume_rip
    movq %rsp, 0x8(%rbx)            # excp->resume_rsp
    movq %r12, 0x10(%rbx)           # excp->resume_r12
    movq %r13, 0x18(%rbx)           # excp->resume_r13
    movq %r14, 0x20(%rbx)           # excp->resume_r14
    movq %r15, 0x28(%rbx)           # excp->resume_r15
    movq %rbx, 0x30(%rbx)           # excp->resume_rbx
    movq %rbp, 0x38(%rbx)           # excp->resume_rbp

    callq *%rcx

excp_res_label:
    movq $0x0, kdbx_in_fixup(%rip)
    popf      # restore eflags
    popq %rbx
    FRAME_END
    ret
ENDPROC(kdbx_call_cmd_func)

