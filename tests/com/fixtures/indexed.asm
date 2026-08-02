; A `switch` compiled the way a C compiler actually compiles one: the table is
; the *displacement* of the jump and the register is the index.
;
;     mov si, ax / cmp si, 3 / jae default / shl si, 1
;     jmp word [cs:si + table]
;
; jumptable.asm covers the other spelling, where a base register is built up by
; hand -- `mov bp, [index] / add bp, table / jmp word [cs:bp]` -- which is what
; Zaxxon does. Both reach the same place and only one of them was being read.
;
; The bug this fixture exists to prevent was a regex: the displacement was
; matched as `(\d+)` while the disassembler prints it as `0x...`, so the whole
; instruction failed to match and the pass said nothing at all. Karateka has
; six tables in this form and lost every one of them -- including one the gap
; sweep then claimed as code, which is the worse failure, because a table read
; as instructions is wrong quietly.
;
; `helper` sits after the table so the run of unclaimed bytes ends there and the
; table's far end is known. Each arm is preceded by a byte that cannot begin an
; instruction, so the gap sweep cannot rescue any of them by accident -- finding
; them proves the jump was read.
;
; `start` calls `helper` for a reason that is not decoration. The table reader
; refuses any target past the last instruction already decoded -- the bound that
; stops it walking off into artwork -- so with nothing reachable behind the arms
; the whole table is rejected and the fixture passes for the wrong reason. One
; `call` over them fixes it, and every real program has such a call somewhere,
; because reachable code is everywhere.

BITS 16
ORG 0x100

start:
    mov ah, 0x09
    mov dx, banner
    int 0x21
    call helper                 ; puts reachable code behind the arms

    mov si, [choice]
    cmp si, 3
    jae done
    shl si, 1
    jmp word [cs:si + table]    ; <- the table is the displacement

done:
    mov ax, 0x4C00
    int 0x21

; ---------------------------------------------------------------------------
    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep
one:
    mov ah, 0x02
    mov dl, 0x41                ; 'A'
    int 0x21
    jmp done

    db 0x0F, 0xFF, 0xFF
two:
    mov ah, 0x02
    mov dl, 0x42                ; 'B'
    int 0x21
    jmp done

    db 0x0F, 0xFF, 0xFF
three:
    mov ah, 0x02
    mov dl, 0x43                ; 'C'
    int 0x21
    jmp done

; ---------------------------------------------------------------------------
table:
    dw one, two, three

; Reachable, so the run above ends here.
helper:
    ret

banner:
    db 'indexed', 0x0D, 0x0A, '$'
choice:
    dw 0
