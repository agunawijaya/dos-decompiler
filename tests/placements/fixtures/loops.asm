; Every loop shape that cost a bug in placements.py, in one .COM file.
;
; The static extractor was developed against Hard Hat Mack and refereed by
; running Hard Hat Mack. That referee found ten bugs in a single session and
; it cannot ship: it needs a copyrighted game. So this is the same program in
; miniature -- a drawer, and one builder per shape -- written here so the
; suite runs anywhere.
;
; Each builder is a shape that was read wrongly at some point, and the comment
; above it says what went wrong. None of them ever *failed*: every one still
; produced a placement, which is why the coverage number never moved and why
; a test that only checks "something came out" would have passed throughout.

BITS 16
ORG 0x100

start:
    call build_countdown
    call build_countup
    call build_two_var
    call build_conditional
    call build_inherits
    call build_zero_shape
    mov ax, 0x4C00
    int 0x21

; ---------------------------------------------------------------------------
; The drawer. Three fixed addresses -- column, row, sprite selector -- and the
; word load into SI is what closes the triple, because a sprite pointer read
; immediately before a blit has no other plausible reading.
; ---------------------------------------------------------------------------
place_sprite:
    mov al, byte [place_col]
    mov dl, byte [place_row]
    mov si, word [shape_select]
    mov di, 0xB800
    mov es, di
    xor di, di
    mov bh, byte [es:di]        ; stand in for the blit
    ret

; ---------------------------------------------------------------------------
; 1. The counted loop that runs *down*: BL is the counter and the index at
;    once, 3 to 0. This is the shape everything else was mistaken for.
;    Expect four placements, columns from cols_a[3..0].
; ---------------------------------------------------------------------------
build_countdown:
    mov bl, 3
    mov byte [loop_index], bl
.again:
    mov al, byte [bx + cols_a]
    mov byte [place_col], al
    mov al, byte [bx + rows_a]
    mov byte [place_row], al
    mov word [shape_select], 0x0500
    call place_sprite
    dec byte [loop_index]
    mov bl, byte [loop_index]
    cmp bl, 0xFF
    je .out
    jmp .again
.out:
    ret

; ---------------------------------------------------------------------------
; 2. The counted loop that runs *up*, to a `cmp`. Read as the down shape it
;    is indices 1 and 0; the program means 1, 2, 3, 4. draw_toolboxes drew two
;    at the wrong rows instead of three at the right ones.
;    Expect four placements, columns from cols_a[1..4].
; ---------------------------------------------------------------------------
build_countup:
    mov bl, 1
    mov byte [loop_index], bl
.again:
    mov al, byte [bx + cols_a]
    mov byte [place_col], al
    mov al, byte [bx + rows_a]
    mov byte [place_row], al
    mov word [shape_select], 0x0600
    call place_sprite
    inc byte [loop_index]
    mov bl, byte [loop_index]
    cmp bl, 5
    je .out
    jmp .again
.out:
    ret

; ---------------------------------------------------------------------------
; 3. The loop kept entirely in memory: one variable counts down, another walks
;    across by two, and neither is in a register except to index a table. With
;    no `mov bl, imm` there is no loop to see at all, and draw_conveyor got
;    one of its four segments.
;    Expect four placements at columns 14, 16, 18, 20.
; ---------------------------------------------------------------------------
build_two_var:
    mov al, 14
    mov byte [cursor], al
    mov al, 3
    mov byte [counter], al
.again:
    mov bl, byte [counter]
    mov al, byte [cursor]
    mov byte [place_col], al
    mov al, byte [bx + rows_a]
    mov byte [place_row], al
    mov word [shape_select], 0x0700
    call place_sprite
    inc byte [cursor]
    inc byte [cursor]
    dec byte [counter]
    js .out
    jmp .again
.out:
    ret

; ---------------------------------------------------------------------------
; 4. A per-slot state byte decides whether the slot is drawn. The walk ran
;    both arms and drew from both, so draw_pits and draw_rivet_row put six
;    sprites on the screen the game never draws. The flag comes from the
;    translation's own idiom: `mov al, X / inc al / dec al` sets Z from AL,
;    which is what LDA did.
;    slots holds 1, 0, 1, 0 -- expect two placements, at slots 3 and 1.
; ---------------------------------------------------------------------------
build_conditional:
    mov bl, 3
    mov byte [loop_index], bl
.again:
    mov al, byte [bx + slots]
    inc al
    dec al
    jne .draw
    jmp .next
.draw:
    mov al, byte [bx + cols_a]
    mov byte [place_col], al
    mov al, byte [bx + rows_a]
    mov byte [place_row], al
    mov word [shape_select], 0x0800
    call place_sprite
.next:
    dec byte [loop_index]
    mov bl, byte [loop_index]
    cmp bl, 0xFF
    je .out
    jmp .again
.out:
    ret

; ---------------------------------------------------------------------------
; 5. A routine that writes no selector at all and draws whatever the last one
;    left. The selector is a real global and it outlives the routine that set
;    it, but callee state is deliberately not merged back into the caller, so
;    it had none.
;    Expect two placements carrying 0x0800 -- what build_conditional left.
; ---------------------------------------------------------------------------
build_inherits:
    mov bl, 1
    mov byte [loop_index], bl
.again:
    mov al, byte [bx + cols_b]
    mov byte [place_col], al
    mov al, byte [bx + rows_b]
    mov byte [place_row], al
    call place_sprite
    inc byte [loop_index]
    mov bl, byte [loop_index]
    cmp bl, 3
    je .out
    jmp .again
.out:
    ret

; ---------------------------------------------------------------------------
; 6. A zero immediate. NASM prints `mov word [sel], 0`, not `0x0000`, and the
;    store pattern required the `0x` form -- so draw_beams, which sets its
;    shape that way and no other, took whatever the previous routine left.
;    Expect one placement with selector 0.
; ---------------------------------------------------------------------------
build_zero_shape:
    mov al, 9
    mov byte [place_col], al
    mov al, 40
    mov byte [place_row], al
    mov word [shape_select], 0
    call place_sprite
    ret

; ---------------------------------------------------------------------------
cols_a:     db 10, 11, 12, 13, 14
rows_a:     db 20, 21, 22, 23, 24
cols_b:     db 30, 31, 32
rows_b:     db 40, 41, 42
slots:      db 1, 0, 1, 0

place_col:      db 0
place_row:      db 0
shape_select:   dw 0
loop_index:     db 0
cursor:         db 0
counter:        db 0
