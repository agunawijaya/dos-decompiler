; A .COM whose routines are reached through a table of addresses.
;
; dispatch.asm covers the other indirect shape, where the program writes a
; constant into a pointer variable and jumps through it. This is the one where
; the pointer is *read out of a table*:
;
;     mov bp, [index] / add bp, table / jmp word [cs:bp]
;
; Zaxxon (1984) keeps its whole level script that way, and about 2,400 bytes
; of routines are reachable only through it -- 57.9% of its code region came
; back as instructions without following the table, 71.3% with it.
;
; A table carries no length, so the interesting question is where it stops.
; This fixture pins both halves of the answer:
;
;   * `table` is bounded by the run of unclaimed bytes it sits in. Nothing
;     reaches the table, so it lies in a gap, and the byte after that gap is
;     already known to be an instruction. `helper` below is reachable, which
;     is what splits the file into two gaps and puts the table in a different
;     one from the routines it names -- the arrangement any real program falls
;     into, because reachable code is everywhere.
;
;   * `decoy` must stop the reader dead. Its first word points at `art`, which
;     lies in the decoy's own gap -- the shape of a table of *data* pointers,
;     which is what Zaxxon's sprite dispatch actually is. A pointer into the
;     same unreached block is no evidence of code, so the table ends there and
;     `three` stays data. regress.py checks for the absence of `mov dl, 0x43`.
;
; The second dispatch sits inside `one`, which is itself reachable only through
; the first table -- so finding it at all requires iterating rather than taking
; one pass. Each hidden routine is preceded by a byte that cannot begin an
; instruction, so the gap sweep cannot rescue any of them by accident.

BITS 16
ORG 0x100

start:
    mov ah, 0x09
    mov dx, banner
    int 0x21
    call helper

    mov bp, [index]             ; 0 or 2 at run time
    add bp, table
    jmp word [cs:bp]            ; <- recursive descent stops dead here

; ---------------------------------------------------------------------------
    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep

one:
    mov ah, 0x02
    mov dl, 0x41                ; 'A'
    int 0x21
    mov bp, decoy               ; the second table, which must not be followed
    jmp word [cs:bp]

    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep again

two:
    mov ah, 0x02
    mov dl, 0x42                ; 'B'
    int 0x21
    mov ax, 0x4C00
    int 0x21

    db 0x0F, 0xFF, 0xFF         ; blocks the gap sweep a third time

three:
    mov ah, 0x02
    mov dl, 0x43                ; 'C' -- must never appear in the output
    int 0x21
    mov ax, 0x4C00
    int 0x21

; ---------------------------------------------------------------------------
; Reached by the call above, so the run of unclaimed bytes ends here and the
; tables below sit in a gap of their own.
helper:
    ret

; Reached by nothing. Only the jump above names it.
table:
    dw one, two
    dw 0xFFFF                   ; outside the segment: the table ends here

decoy:
    dw art                      ; a data pointer, in this same unreached block
    dw three                    ; never read, because the scan stopped above
art:
    db 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55

banner:
    db 'jumptable', 0x0D, 0x0A, '$'
index:
    dw 0
