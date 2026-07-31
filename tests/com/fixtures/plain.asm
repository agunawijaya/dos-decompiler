; A single-segment .COM: the ordinary case.
;
; Exercises the two things that decide whether the output is readable rather
; than merely correct -- stopping the walk at the DOS exit call instead of
; disassembling the message that follows it, and printing that message as text.

BITS 16
ORG 0x100

start:
    mov ah, 0x09
    mov dx, banner
    int 0x21

    mov si, prompt
.show:
    cld
    lodsb
    cmp al, 0
    je .wait
    mov ah, 0x0E
    mov bh, 0
    int 0x10
    jmp .show

.wait:
    mov ah, 0
    int 0x16
    cmp al, 'q'
    je .bye
    cmp al, 'Q'
    jne .wait

.bye:
    mov ax, 0x4C00
    int 0x21

banner:
    db 'A plain COM file, one segment, nothing clever.', 0x0D, 0x0A, '$'
prompt:
    db 0x0D, 0x0A, 'Press Q to quit.', 0
table:
    db 0x00, 0x28, 0x50, 0x78, 0xA0, 0xC8, 0xF0, 0x18
    db 0x01, 0x29, 0x51, 0x79, 0xA1, 0xC9, 0xF1, 0x19
