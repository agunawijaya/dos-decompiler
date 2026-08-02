; A .COM whose routines are reached only through a `switch` table that sits
; directly behind them, with nothing anywhere naming the table.
;
; jumptable.asm covers the case where a decoded `jmp word [cs:bp]` points at
; the table. That detection is circular when the jump lives in code that is
; itself unreached: the reader and the table are unreachable *together*, and
; neither can be used to find the other. Karateka (1984) is that case four
; times over, and it cost 6.9 points of its code region -- 85.0% without this,
; 91.9% with it.
;
; The arrangement below is what a C compiler emits: the arms first, the table
; immediately behind them, and the whole thing in one run of unclaimed bytes.
;
;   * `helper` is reachable, so the run of unclaimed bytes stops there. That is
;     what makes "the table ends where the run ends" a usable constraint rather
;     than a guess -- and it is why `helper` is placed *after* the table.
;
;   * The case value `0x006D` puts a `6D` byte in the run. `6D` is `insw`, an
;     instruction no game executes, so the gap sweep vetoes the whole run --
;     twenty-one bytes of arms discarded on the strength of two bytes of table.
;     That veto is correct and it is all-or-nothing, which is the gap this
;     fixture exists to hold open. Real tables carry bytes like this constantly;
;     Karateka's four all do.
;
;   * `decoy` is the negative control, and it is the one that matters. It is a
;     well-formed (case, target) table -- three distinct targets, all real
;     routines, small case values -- so every content test passes. What it does
;     not have is code in front of it: the `0x0F, 0xFF, 0xFF` blocks linear
;     disassembly, so the run cannot be read as "a function with a table behind
;     it" and must be refused. regress.py checks for the absence of
;     `mov dl, 0x58`.
;
;     Without that requirement the pass is a table scanner, and a table scanner
;     loose in a data segment is how artwork becomes code. Hard Hat Mack was
;     the proof: fourteen `02` bytes in a row, based at 0x0100, read as seven
;     copies of the address 0x0202, each one walking to a return.

BITS 16
ORG 0x100

start:
    mov ah, 0x09
    mov dx, banner
    int 0x21
    call helper
    mov ax, 0x4C00
    int 0x21

; ---------------------------------------------------------------------------
; Reached by nothing. Only the table below names these.
arm_a:
    mov ah, 0x02
    mov dl, 0x41                ; 'A'
    int 0x21
    ret
arm_b:
    mov ah, 0x02
    mov dl, 0x42                ; 'B'
    int 0x21
    ret
arm_c:
    mov ah, 0x02
    mov dl, 0x43                ; 'C'
    int 0x21
    ret

; The table, flush against the arms. Read backwards from the end of the run.
cases:
    dw 0x006D, arm_a            ; 0x6D is `insw`: the sweep stops here
    dw 0x0041, arm_b
    dw 0x0042, arm_c

; ---------------------------------------------------------------------------
; Reachable, so the run above ends here and the table's far end is known.
helper:
    ret

; ---------------------------------------------------------------------------
; The negative control: a table with no function in front of it.
    db 0x0F, 0xFF, 0xFF         ; cannot begin an instruction

decoy:
    dw 0x0002, never_a
    dw 0x0003, never_b
    dw 0x0004, never_c

never_a:
    mov ah, 0x02
    mov dl, 0x58                ; 'X' -- must never appear in the output
    int 0x21
    ret
never_b:
    mov ah, 0x02
    mov dl, 0x59                ; 'Y'
    int 0x21
    ret
never_c:
    mov ah, 0x02
    mov dl, 0x5A                ; 'Z'
    int 0x21
    ret

banner:
    db 'casetable', 0x0D, 0x0A, '$'
