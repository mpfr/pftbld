
PROG=		pftbld
SRCS=		parse.y
SRCS+=		config.c listener.c log.c logger.c persist.c pftbld.c
SRCS+=		scheduler.c sockpipe.c tinypfctl.c util.c
MAN=		pftblctl.8 pftbld.8 pftbld.conf.5

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
		${.CURDIR}/pftblctl.sh ${DESTDIR}${BINDIR}/pftblctl

uninstall:
	-rm ${BINDIR}/pftbl* ${MANDIR}{5,8}/pftbl*

CONFFILE=	pftbld.conf

.if exists(${.CURDIR}/../pkg/pftbld.rc) && exists(${.CURDIR}/../pkg/${CONFFILE})

CONFDIR=	/etc/pftbld
USER=		_pftbld

fullinstall: install
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/../pkg/pftbld.rc /etc/rc.d/pftbld
	@-if test "$$(userinfo -e ${USER}; echo $$?)" != '0'; then echo "useradd -c 'pftbld unprivileged user' -d /var/empty -g =uid -r 100..999 -s /sbin/nologin ${USER}" && useradd -c 'pftbld unprivileged user' -d /var/empty -g =uid -r 100..999 -s /sbin/nologin ${USER}; elif test "$$(groupinfo -e ${USER}; echo $$?)" != '0'; then echo "groupadd ${USER}" && groupadd ${USER}; fi
	@-if test -f ${CONFDIR}/${CONFFILE}; then echo "(configuration file exists, not touching ${CONFDIR}/${CONFFILE})"; else mkdir -p ${CONFDIR} && echo "cp ${.CURDIR}/../pkg/${CONFFILE} ${CONFDIR}" && cp ${.CURDIR}/../pkg/${CONFFILE} ${CONFDIR}; fi

fulluninstall: uninstall
	-rm /etc/rc.d/pftbld
	-userdel ${USER}
	-groupdel ${USER}
	@-if test -d ${CONFDIR}; then if test -z "$$(diff -x pftbld.rc -aqr ${.CURDIR}/../pkg ${CONFDIR})"; then echo "rm -r ${CONFDIR}" && rm -r ${CONFDIR}; else echo "(configuration directory has changed, not touching ${CONFDIR})"; fi; fi

reinstall: fulluninstall fullinstall

update: all fullinstall

.endif

.include <bsd.prog.mk>
