; A .COM whose real work is entered through an indirect jump.
;
; `jmp word [state]` ends a recursive-descent walk. Everything past it is
; invisible, and the effect is not marginal: Hard Hat Mack (1983) reaches 236
; of its 9,086 instructions from the entry point, because the whole game sits
; behind one such jump.
;
; The pointer is not computed, though. It is written as a constant, which is
; what a state machine of this era does, and that makes the target recoverable
; without emulating anything: find the jump, find the instruction that stores
; an immediate into the same word, and that immediate is an entry point.
;
; Two things this fixture has to get right, or it proves nothing:
;
;   - The gap sweep must not be able to rescue the hidden routines. Each one is
;     preceded by a byte that cannot begin a valid instruction, so the run of
;     unreferenced bytes does not decode cleanly and the sweep declines it.
;   - The second state must be reachable *only* from the first, so a single
;     pass is not enough. Recovering `two` requires having already reached
;     `one`, which is why the detection has to iterate to a fixed point.

BITS 16
ORG 0x100

start:
    mov word [state], one       ; the first state, as a constant
    mov ah, 0x09
    mov dx, banner
    int 0x21

run:
    jmp word [state]            ; <- recursive descent stops dead here

; ---------------------------------------------------------------------------
; Nothing branches here. Only the constant above names it.
    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep

one:
    mov ah, 0x02
    mov dl, 'A'
    int 0x21
    mov word [state], two       ; reachable only once `one` itself is reached
    jmp run

    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep again

two:
    mov ah, 0x02
    mov dl, 'B'
    int 0x21
    mov word [low], three       ; the same trick, through a one-digit address
    call word [low]
    mov ax, 0x4C00
    int 0x21

    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep a third time

; ---------------------------------------------------------------------------
; Reached only through a pointer kept at [9] -- inside the program's own PSP,
; which a .COM is free to use as scratch once it has read the command line.
; Zaxxon keeps its per-scene collision routine there and calls nine different
; routines through it.
;
; This is a separate case from the two above and it is not a variation on
; style. Capstone prints a one-digit address without the 0x prefix, so this
; instruction disassembles as `call word [9]`, and a detector matching only
; `0x[0-9a-f]+` skips it in silence. That cost Zaxxon nine routines.
three:
    mov ah, 0x02
    mov dl, 'C'
    int 0x21
    ret

banner:
    db 'dispatch', 0x0D, 0x0A, '$'
state:
    dw 0

low equ 9
