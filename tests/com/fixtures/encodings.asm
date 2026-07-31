; Instructions written the way a 1980s assembler wrote them, not the way NASM
; prefers to write them today.
;
; Every pair below means the same thing and differs only in encoding. NASM
; picks the short form; the file holds the long one. Reproducing the file
; means reproducing its choices, so this fixture is where comrec's `strict`
; retry and its byte-pinning fallback are exercised. Take either away and the
; rebuild stops being byte-identical.

BITS 16
ORG 0x100

start:
    ; Accumulator forms: NASM would emit 83 /0 ib here.
    db 0x05, 0x11, 0x00         ; add ax, 0x0011  (long form)
    db 0x2D, 0x08, 0x00         ; sub ax, 0x0008
    db 0x3D, 0x40, 0x00         ; cmp ax, 0x0040
    db 0x35, 0x30, 0x00         ; xor ax, 0x0030

    ; Direction-bit alternates: 8B /r instead of 89 /r. Same registers, same
    ; effect, different byte. NASM has no syntax that selects it, so these can
    ; only come back as pinned bytes carrying their disassembly in a comment.
    db 0x8B, 0xD0               ; mov dx, ax
    db 0x8B, 0xD8               ; mov bx, ax
    db 0x8A, 0xC4               ; mov al, ah
    db 0x03, 0xFB               ; add di, bx
    db 0x3B, 0xDA               ; cmp bx, dx

    ; Reachable code after the pinned run, to prove the walk survives it.
    mov cx, 0x10
.spin:
    dec cx
    jnz .spin

    mov ax, 0x4C00
    int 0x21
