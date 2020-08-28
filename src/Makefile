
PROG=		pftbld
SRCS=		parse.y
SRCS+=		config.c listener.c log.c logger.c persist.c pftbld.c
SRCS+=		scheduler.c sockpipe.c tinypfctl.c util.c
MAN=		pftblctl.8 pftbld.8 pftbld.conf.5

SCRIPT=		pftblctl.sh

LDADD+=		-lpthread
DPADD+=		${LIBPTHREAD}
#DEBUG=		-g -DDEBUG=3 -O0
CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -Wcast-qual
COPTS+=		-Werror-implicit-function-declaration
YFLAGS=

BINDIR?=	/usr/local/sbin
MANDIR?=	/usr/local/man/man

afterinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/${SCRIPT} ${DESTDIR}${BINDIR}/pftblctl

.include <bsd.prog.mk>
