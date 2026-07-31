; A .COM that reloads CS and continues at a fresh base, the way ParaTrooper
; does. The layout is:
;
;   file 0x0000  a six-instruction stub, addressed from 0x100 as usual
;   file 0x0010  data -- messages and tables, reached through DS
;   file 0x0200  the real code, addressed from 0, reached by a far return
;
; Everything after the stub disassembles against the wrong base unless the
; split is found, so this fixture fails loudly if detect_layout() breaks.
;
; The stub ends with `mov ax, ds` so the code segment starts with AX holding
; the PSP segment; `add ax, 0x11 / mov ds, ax` then puts DS 0x110 bytes into
; the file, which is what ties `mov si, 0x1234` to a row of the dump.

BITS 16

section .stub start=0 vstart=0x100
    mov ax, cs
    add ax, 0x30            ; (0x30 << 4) - 0x100 = file offset 0x200
    push ax
    xor ax, ax
    push ax
    mov ax, ds
    retf

section .data start=0x10 vstart=0x110
greeting:
    db 0x0D, 0x0A, 'Reached the second segment.', 0
rows:
    dw 0x0000, 0x0068, 0x00D0, 0x0138, 0x01A0, 0x0208, 0x0270, 0x02D8

section .code start=0x200 vstart=0
main:
    add ax, 0x11            ; DS := PSP + 0x11, so DS:0 is file offset 0x10
    mov ds, ax
    mov si, greeting - 0x110
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
    mov bx, [rows - 0x110 + 4]
    mov ax, 0x4C00
    int 0x21
