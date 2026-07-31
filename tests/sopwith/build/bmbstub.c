/* bmbstub.c -- the unreleased BMB block-I/O layer, stubbed.
   SWMULTIO.C references these; no published file defines them. */
int bopen( name, mode ) char *name; int mode; { return -1; }
int bseek( fd, off, wh ) int fd; long off; int wh; { return -1; }
int bread( fd, buf, n ) int fd; char *buf; unsigned n; { return -1; }
int bwrite( fd, buf, n ) int fd; char *buf; unsigned n; { return -1; }
int bioerr( fd ) int fd; { return 1; }

/* ctype as functions. BMBLIB.C and SWSOUND.C call these without including
   <ctype.h>, so the usual macros never apply and the linker wants real
   symbols. The original build got them from the unreleased BMB library. */
int isalpha( c ) int c; { return (c>='A'&&c<='Z')||(c>='a'&&c<='z'); }
int isdigit( c ) int c; { return c>='0'&&c<='9'; }
int isalnum( c ) int c; { return isalpha(c)||isdigit(c); }
