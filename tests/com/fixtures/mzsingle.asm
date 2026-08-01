; An MZ executable that is really a .COM wearing a header.
;
; One segment, and an entry stub that sets the segment registers once and never
; thinks about them again. Karateka (1984) is 87,990 bytes of exactly this:
; four relocations, 0.4 stack frames per KB, hand-written assembly.
;
; The MZ pipeline is the wrong tool for these. It loads the file into Ghidra,
; applies relocations and hands back segments, and what comes out is "readable,
; probably right". The .COM route reaches a rebuild that is byte-identical and
; says so -- a stronger claim about the same program, available only because
; the program does not really use segments.
;
; What this fixture proves is that comrec strips the header and reconstructs
; the *image*, not the file. Getting that wrong is not loud: a reconstruction
; that treats the 512-byte header as code still rebuilds the file exactly,
; still prints BYTE-IDENTICAL, and is wrong about every address in the program
; by 512. That bug was written here and survived one full run before the file
; sizes gave it away.
;
; The needles are therefore addresses. `L_00002` can only appear if the entry
; came from CS:IP with the header already off; reconstructing the whole file
; would label the same instruction `L_00202`.
;
; The header is written out by hand rather than by a linker, so the fixture
; builds with `nasm -f bin` like every other one here, and so the bytes under
; test are visible in the source.

BITS 16
ORG 0

HDR_PARAS   equ 32                      ; 512-byte header
IMAGE_LEN   equ image_end - image_start
TOTAL       equ HDR_PARAS * 16 + IMAGE_LEN

; ---------------------------------------------------------------- MZ header
    db 'MZ'
    dw TOTAL % 512                      ; bytes used in the last page
    dw (TOTAL + 511) / 512              ; pages
    dw 0                                ; relocations: none needed here
    dw HDR_PARAS                        ; header size, in paragraphs
    dw 0x0010                           ; minalloc
    dw 0xFFFF                           ; maxalloc
    dw 0x1000                           ; initial SS, relative to the image
    dw 0x0100                           ; initial SP
    dw 0                                ; checksum
    dw 0x0002                           ; initial IP  -- image offset 2
    dw 0x0000                           ; initial CS
    dw 0x001C                           ; relocation table offset
    dw 0                                ; overlay number
    times HDR_PARAS * 16 - ($ - $$) db 0

; ------------------------------------------------------------- load image
image_start:
    dw 0xFFFC                           ; two bytes the entry point steps over

; IP = 2 lands here. A reconstruction that kept the header would call this
; L_00202 instead of L_00002.
    cli
    mov ax, cs
    mov ds, ax
    mov ss, ax
    mov sp, 0x100
    sti

    mov ah, 0x30                        ; DOS version, the way Karateka opens
    int 0x21
    or al, al
    jne .ok
    mov ax, 1
.ok:
    mov word [ready - image_start], ax

    mov ah, 0x09
    mov dx, banner - image_start
    int 0x21

    call work
    mov ax, 0x4C00
    int 0x21

; Reached only by the call above, so recursive descent has to walk to it.
work:
    mov cx, 4
.spin:
    push cx
    mov ah, 0x02
    mov dl, 'z'
    int 0x21
    pop cx
    loop .spin
    ret

    db 0x0F, 0xFF, 0xFF                 ; the sweep must not swallow the data

banner:
    db 'single segment', 0x0D, 0x0A, '$'
ready:
    dw 0
image_end:
