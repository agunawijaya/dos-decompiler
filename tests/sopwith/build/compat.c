/* compat.c -- the pieces the GPL source release does not contain.
 *
 * Two distinct gaps are filled here, and they are NOT equivalent:
 *
 *   1. C runtime functions (malloc, exit, ctype, strncmp). The original build
 *      took these from the Microsoft C library. Providing them here keeps the
 *      ground-truth binary self-contained and free of a foreign runtime whose
 *      functions would pollute the function inventory.
 *
 *   2. The "BMB" block I/O layer (bopen/bseek/bread/bwrite/bioerr). These are
 *      referenced by SWMULTIO.C but defined nowhere in the release -- they
 *      lived in David Clark's in-house library, which was never published.
 *      They are stubbed. Multiplayer disk-passing therefore does not work in
 *      the ground-truth build. Single-player, which is what the validation
 *      exercises, does not touch them.
 *
 * Compiled with -ecc so every symbol gets the leading-underscore, stack-based
 * decoration the assembly modules expect.
 */

/* ---- storage ------------------------------------------------------------
 * Sopwith calls malloc exactly once, for the object pool. A bump allocator
 * over a static buffer reproduces that behaviour without dragging in the
 * heap manager (whose dozens of functions would otherwise show up as
 * unidentifiable noise in the decompiled output).
 */
#define POOL_BYTES 13000

static char pool[POOL_BYTES];
static unsigned pool_used = 0;

char *malloc(unsigned size)
{
    char *p;

    if (size == 0 || pool_used + size > POOL_BYTES) {
        return (char *)0;
    }
    p = &pool[pool_used];
    pool_used += (size + 1) & ~1U;   /* keep the pool word-aligned */
    return p;
}

void free(char *p)
{
    /* The original never frees; nothing to do. */
    (void)p;
}

/* ---- process ------------------------------------------------------------ */

extern void dos_terminate(int code);
#pragma aux dos_terminate =     \
    "mov ah, 4ch"               \
    "int 21h"                   \
    parm [al]                   \
    modify [ax];

void exit(int code)
{
    dos_terminate(code);
}

/* ---- ctype -------------------------------------------------------------- */

int isalpha(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

int isdigit(int c)
{
    return c >= '0' && c <= '9';
}

int isalnum(int c)
{
    return isalpha(c) || isdigit(c);
}

int toupper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c;
}

int tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/* ---- string ------------------------------------------------------------- */

int strncmp(char *a, char *b, unsigned n)
{
    while (n-- > 0) {
        if (*a != *b) {
            return (unsigned char)*a - (unsigned char)*b;
        }
        if (*a == '\0') {
            return 0;
        }
        a++;
        b++;
    }
    return 0;
}

/* ---- numeric conversion ------------------------------------------------- */

long strtol(char *s, char **end, int base)
{
    long value = 0;
    int negative = 0;

    while (*s == ' ' || *s == '\t') {
        s++;
    }
    if (*s == '-') {
        negative = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    if (base == 0) {
        base = (*s == '0' && (s[1] == 'x' || s[1] == 'X')) ? 16 : 10;
    }
    if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    for (;;) {
        int digit;

        if (isdigit(*s)) {
            digit = *s - '0';
        } else if (isalpha(*s)) {
            digit = toupper(*s) - 'A' + 10;
        } else {
            break;
        }
        if (digit >= base) {
            break;
        }
        value = value * base + digit;
        s++;
    }
    if (end != (char **)0) {
        *end = s;
    }
    return negative ? -value : value;
}

int atoi(char *s)
{
    return (int)strtol(s, (char **)0, 10);
}

/* ---- port I/O ----------------------------------------------------------- */

/* A #pragma aux function is inlined, so it emits no symbol other modules can
 * link against. The pragma provides the instruction; a real function wraps it
 * so that BMBLIB.C's inportb/outportb resolve. */
int port_in(unsigned port);
#pragma aux port_in =           \
    "in al, dx"                 \
    "xor ah, ah"                \
    parm [dx]                   \
    value [ax];

int port_out(unsigned port, int value);
#pragma aux port_out =          \
    "out dx, al"                \
    parm [dx] [ax]              \
    value [ax];

int inp(unsigned port)
{
    return port_in(port);
}

int outp(unsigned port, int value)
{
    return port_out(port, value);
}

/* ---- BMB block I/O (unreleased library, stubbed) ------------------------ */

int bopen(char *name, int mode)
{
    (void)name;
    (void)mode;
    return -1;                  /* always "cannot open" */
}

int bseek(int fd, long offset, int whence)
{
    (void)fd;
    (void)offset;
    (void)whence;
    return -1;
}

int bread(int fd, char *buf, unsigned count)
{
    (void)fd;
    (void)buf;
    (void)count;
    return -1;
}

int bwrite(int fd, char *buf, unsigned count)
{
    (void)fd;
    (void)buf;
    (void)count;
    return -1;
}

int bioerr(int fd)
{
    (void)fd;
    return 1;                   /* an error is always pending */
}
