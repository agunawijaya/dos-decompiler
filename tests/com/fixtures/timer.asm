; A .COM that installs a timer handler without ever writing `es:`.
;
; interrupt.asm covers the textbook install -- ES pointed at zero and the slot
; written as an absolute offset, `xchg word [es:0x24], ax`. Zaxxon (1984) does
; the same job with a base register instead:
;
;     xor cx, cx / mov ds, cx / mov bx, 0x70 / mov word [bx], dx
;
; There is no `es:` in it and no constant that looks like a vector slot, so a
; detector that matches the absolute form alone finds nothing. That left
; Zaxxon's whole 47-byte timer handler in the file as data, and with it every
; conclusion about how the game keeps time.
;
; As in interrupt.asm, the handler is followed by a byte that cannot begin an
; instruction, so the gap sweep cannot rescue it by accident. If its
; instructions come back, the install was read.

BITS 16
ORG 0x100

start:
    cli
    in al, 0x21
    and al, 0xFE                ; unmask IRQ0, the periodic timer
    out 0x21, al

    push ds
    mov ax, cs                  ; the handler's segment
    lea dx, [handler]           ;   and its offset
    xor cx, cx
    mov ds, cx                  ; DS -> the interrupt vector table
    mov bx, 0x70                ; 0x70 / 4 = vector 0x1C, the timer tick
    mov word [bx], dx
    mov word [bx + 2], ax
    pop ds
    sti

    mov ah, 0x09
    mov dx, banner
    int 0x21

.wait:
    cmp byte [ticks], 0
    je .wait

    mov ax, 0x4C00
    int 0x21

; ---------------------------------------------------------------------------
; Unreachable by any branch. Only the vector points here.
handler:
    push ax
    mov al, byte [cs:ticks]
    inc al
    mov byte [cs:ticks], al
    pop ax
    iret

; A byte that cannot start an instruction, so the sweep cannot claim the run
; above by decoding it cleanly to the end.
    db 0x0F, 0xFF, 0xFF

banner:
    db 'Waiting for a tick.', 0x0D, 0x0A, '$'
ticks:
    db 0
