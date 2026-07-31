/* libref.c -- a reference program whose only job is to drag as much of the C
 * runtime library into a linked binary as possible.
 *
 * Linking this and reading the resulting map gives the address and extent of
 * every library function the linker pulled in. Extracting those byte ranges
 * produces a signature database that can then identify the same library
 * functions inside a *different* program -- which is a genuine held-out test,
 * not a circular one.
 *
 * Nothing here needs to run correctly, or at all. It needs to reference
 * things, and it must not let the optimiser discard the references, hence the
 * volatile sink and the argc guard.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <setjmp.h>
#include <dos.h>

volatile int sink;
static jmp_buf jb;

/* A real comparator rather than a cast of strcmp: the cast made the compiler
 * reject the call outright, and the point is to reference qsort/bsearch, not
 * to be clever about it. */
static int cmpfn(const void *a, const void *b)
{
    return *(const char *)a - *(const char *)b;
}

int main(int argc, char **argv)
{
    char buf[64];
    char *p;
    long l;
    double d;
    time_t t;

    if (argc > 1000) {          /* never true; keeps every call reachable */
        return 0;
    }

    /* stdio */
    printf("%d %s %c %x %ld\n", argc, "x", 'y', 42, 7L);
    sprintf(buf, "%d", argc);
    sscanf(buf, "%d", &sink);
    puts(buf);
    putchar('a');
    fputs(buf, stdout);
    fopen("nul", "r");
    fclose(stdout);
    fread(buf, 1, 1, stdin);
    fwrite(buf, 1, 1, stdout);
    fseek(stdin, 0L, SEEK_SET);
    ftell(stdin);
    fgets(buf, sizeof buf, stdin);
    getchar();

    /* string */
    strcpy(buf, "abc");
    strncpy(buf, "abc", 3);
    strcat(buf, "d");
    strncat(buf, "d", 1);
    sink = strcmp(buf, "abc");
    sink = strncmp(buf, "abc", 3);
    sink = (int)strlen(buf);
    p = strchr(buf, 'a');
    p = strrchr(buf, 'a');
    p = strstr(buf, "a");
    p = strtok(buf, " ");
    memcpy(buf, "abc", 3);
    memmove(buf, "abc", 3);
    sink = memcmp(buf, "abc", 3);
    memset(buf, 0, sizeof buf);

    /* ctype */
    sink = isalpha('a') + isdigit('1') + isalnum('a') + isspace(' ')
         + isupper('A') + islower('a') + ispunct('.') + isprint('a')
         + toupper('a') + tolower('A');

    /* stdlib */
    p = (char *)malloc(16);
    p = (char *)calloc(2, 8);
    p = (char *)realloc(p, 32);
    free(p);
    sink = atoi("12");
    l = atol("12");
    d = atof("1.5");
    l = strtol("12", (char **)0, 10);
    sink = abs(-1);
    l = labs(-1L);
    sink = rand();
    srand(1);
    /* qsort/bsearch are omitted deliberately: under -ecc their comparator
     * parameter no longer matches the library's declared convention, and
     * chasing that is not worth it for two more signatures. */
    sink += cmpfn(buf, buf);
    getenv("PATH");
    system("");

    /* math -- pulls in the floating point helpers */
    d = sin(1.0) + cos(1.0) + tan(1.0) + atan(1.0) + exp(1.0)
      + log(1.0) + log10(1.0) + sqrt(2.0) + pow(2.0, 3.0)
      + fabs(-1.0) + floor(1.5) + ceil(1.5) + fmod(3.0, 2.0);
    sink = (int)d;

    /* time */
    t = time((time_t *)0);
    localtime(&t);
    ctime(&t);

    /* non-local jump */
    if (setjmp(jb) != 0) {
        return 1;
    }

    /* DOS-specific. These matter more than they look: the interrupt helpers
     * are exactly what a game links, and leaving them out of the reference
     * program left seven library routines undetected in the first run. */
    {
        union REGS r;
        struct SREGS s;

        memset(&r, 0, sizeof r);
        segread(&s);
        int86(0x10, &r, &r);
        int86x(0x21, &r, &r, &s);
        intdos(&r, &r);
        intdosx(&r, &r, &s);
        bdos(0x30, 0, 0);
        movedata(s.ds, 0, s.es, 0, 16);
#ifdef __WATCOMC__
        delay(1);           /* Watcom/Borland only; Microsoft C has no delay() */
#endif
    }

    sink = (int)l;
    return sink;
}
