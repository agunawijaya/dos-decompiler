; A .COM whose entry stub is hidden behind a jump over a text banner.
;
; ParaTrooper's far-return stub is the first thing in its file, so abstract
; evaluation starting at offset 0 walks straight into it. Zaxxon (1984) does
; not oblige: the file opens with `jmp 0x180` over twenty lines of title text,
; and the stub sits on the far side of it. Evaluating from offset 0 and
; treating the jump as the end of the stub recovered nine instructions out of
; 20,736 bytes -- a rebuild that was byte-identical and told you nothing.
;
; The layout here is that shape, in miniature:
;
;   file 0x0000  a jump over the banner
;   file 0x0002  banner text, never executed
;   file 0x0061  the stub, addressed from 0x100 as usual
;   file 0x0080  data -- messages and tables, reached through DS
;   file 0x0200  the real code, addressed from 0, reached by a far return
;
; What has to come back is exactly what farstub.asm demands, because the
; outcome must be the same; the only difference is that the stub had to be
; found first. If detect_layout() stops following the jump, the split is
; missed, nothing past the stub is reached, and the floor in regress.py fails.

BITS 16

section .stub start=0 vstart=0x100
    jmp stub

banner:
    db 0x0D, 0x0A, 'Fixture: the stub is behind this banner.', 0x0D, 0x0A
    db '        -- a jump over data, then a far return --', 0x0D, 0x0A, '$'

stub:
    mov ax, cs
    add ax, 0x30            ; (0x30 << 4) - 0x100 = file offset 0x200
    push ax
    xor ax, ax
    push ax
    mov ax, ds
    retf

section .data start=0x80 vstart=0x180
greeting:
    db 0x0D, 0x0A, 'Reached the second segment.', 0
rows:
    dw 0x0000, 0x0068, 0x00D0, 0x0138, 0x01A0, 0x0208, 0x0270, 0x02D8

section .code start=0x200 vstart=0
main:
    add ax, 0x18            ; DS := PSP + 0x18, so DS:0 is file offset 0x80
    mov ds, ax
    mov si, greeting - 0x180
.show:
    cld
    lodsb
    cmp al, 0
    je .done
    mov ah, 0x0E
    mov bh, 0
    int 0x10
    jmp .show
.done:
    mov bx, [rows - 0x180 + 4]
    mov ax, 0x4C00
    int 0x21
