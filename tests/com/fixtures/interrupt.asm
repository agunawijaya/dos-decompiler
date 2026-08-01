; A .COM that installs its own keyboard interrupt handler.
;
; The handler is an entry point that nothing branches to — the hardware calls
; it. Recursive descent from the program's entry can never reach it, so the
; only way to find it is to read the code that writes the vector.
;
; The gap sweep must not be able to rescue it here. The handler is followed
; immediately by a byte that does not begin a valid instruction, so the run of
; unreferenced bytes does not decode cleanly to its end and the sweep declines
; it. If comrec still returns the handler as instructions, it found the install.
;
; Modelled on Hard Hat Mack (1983), which takes over INT 9 to read scancodes
; directly and translate them through its own table.

BITS 16
ORG 0x100

start:
    cli
    xor ax, ax
    mov es, ax                  ; ES -> the interrupt vector table
    lea ax, [handler]
    mov bx, cs
    xchg word [es:0x24], ax     ; 0x24 / 4 = vector 9
    xchg word [es:0x26], bx
    mov word [old_off], ax      ; keep the old vector to restore later
    mov word [old_seg], bx
    sti

    mov ah, 0x09
    mov dx, banner
    int 0x21

.wait:
    cmp byte [pressed], 0
    je .wait

    cli                         ; put the old handler back
    xor ax, ax
    mov es, ax
    mov ax, [old_off]
    mov bx, [old_seg]
    mov word [es:0x24], ax
    mov word [es:0x26], bx
    sti

    mov ax, 0x4C00
    int 0x21

; ---------------------------------------------------------------------------
; Unreachable by any branch. Only the vector points here.
handler:
    push ax
    in al, 0x60                 ; scancode straight off the keyboard port
    mov byte [cs:pressed], al
    in al, 0x61                 ; pulse the acknowledge line
    or al, 0x80
    out 0x61, al
    and al, 0x7F
    out 0x61, al
    mov al, 0x20                ; end-of-interrupt to the PIC
    out 0x20, al
    pop ax
    iret

; A byte that cannot start an instruction, so the sweep cannot claim the run
; above by decoding it cleanly to the end.
    db 0x0F, 0xFF, 0xFF

banner:
    db 'Press any key.', 0x0D, 0x0A, '$'
pressed:
    db 0
old_off:
    dw 0
old_seg:
    dw 0
