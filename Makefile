# $OpenBSD: Makefile,v 1.4 2017/04/05 14:43:14 reyk Exp $

PROG=	dhcping
SRCS=	dhcping.c
MAN=	
LDADD=	-levent
DPADD=	${LIBEVENT}

CFLAGS+=-Wall
CFLAGS+=-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations
CFLAGS+=-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare
DEBUG=-g

BINDIR=/opt/local/sbin
MANDIR=/opt/local/share/man/man

.include <bsd.prog.mk>
