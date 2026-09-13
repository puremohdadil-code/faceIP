; SentinelMesh optional x64 checksum primitive.
; Input: RCX = pointer, RDX = byte count. Output: RAX = byte sum.
; The host must validate both pointer ownership and length before calling.

section .text
global sm_checksum

sm_checksum:
    xor rax, rax
    xor r8, r8
.loop:
    cmp r8, rdx
    jae .done
    movzx r9, byte [rcx + r8]
    add rax, r9
    inc r8
    jmp .loop
.done:
    ret
