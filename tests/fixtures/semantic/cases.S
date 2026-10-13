/* Repository-owned Windows x64 fixtures. The native oracle uses the same bytes. */
.text
.globl fixture_conditional
fixture_conditional:
    cmp $0, %ecx
    je 1f
    mov $1, %eax
    ret
1:  xor %eax, %eax
    ret

.globl fixture_imul
fixture_imul:
    imul $7, %ecx, %eax
    ret

.globl fixture_partial
fixture_partial:
    mov $0x1234, %rax
    mov $0x56, %al
    ret

.globl fixture_movzx
fixture_movzx:
    mov $0x1234, %rax
    movzbl %al, %eax
    ret

.globl fixture_indexed_lea
fixture_indexed_lea:
    lea -8(%rcx,%rdx,8), %rax
    ret

.globl fixture_string
fixture_string:
    lea fixture_message(%rip), %rax
    ret

.section .rdata,"dr"
fixture_message:
    .asciz "REA comparative fixture"
