
PROG=		pftbld
SRCS=		parse.y
SRCS+=		config.c listener.c log.c logger.c persist.c pftbld.c
SRCS+=		scheduler.c sockpipe.c tinypfctl.c util.c
MAN=		pftblctl.8 pftbld.8 pftbld.conf.5

SCRIPT=		pftblctl

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
		${.CURDIR}/${SCRIPT}.sh ${DESTDIR}${BINDIR}/${SCRIPT}

.if exists(${.CURDIR}/../pkg/pftbld.rc) && exists(${.CURDIR}/../pkg/${CONFFILE})

CONFDIR=	/etc/pftbld
CONFFILE=	pftbld.conf
USER=		_pftbld

fullinstall: install
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} \
		${.CURDIR}/../pkg/pftbld.rc /etc/rc.d/pftbld
	@if test "$$(userinfo -e ${USER}; echo $$?)" = "0"; then echo "userdel ${USER}" && userdel ${USER}; fi
	@if test "$$(groupinfo -e ${USER}; echo $$?)" = "0"; then echo "groupdel ${USER}" && groupdel ${USER}; fi
	useradd -c "pftbld unprivileged user" -d /var/empty -g =uid -r 100..999 -s /sbin/nologin ${USER}
	@-if test -f ${CONFDIR}/${CONFFILE}; then echo "--> configuration exists, not touching ${CONFDIR}/${CONFFILE}"; else mkdir -p ${CONFDIR} && echo "cp ${.CURDIR}/../pkg/${CONFFILE} ${CONFDIR}" && cp ${.CURDIR}/../pkg/${CONFFILE} ${CONFDIR}; fi

uninstall:
	-rm /etc/rc.d/pftbld ${MANDIR}{5,8}/pftbl* ${BINDIR}/pftbl*
	-userdel ${USER}
	-groupdel ${USER}
	@-if test -f ${CONFDIR}/${CONFFILE} -a $$(ls ${CONFDIR} | wc -l) -eq 1 -a "$$(cmp -s ${.CURDIR}/../pkg/${CONFFILE} ${CONFDIR}/${CONFFILE}; echo $$?)" = "0"; then echo "rm -r ${CONFDIR}" && rm -r ${CONFDIR}; else echo "--> configuration has changes, not touching ${CONFDIR}"; fi

.endif

.include <bsd.prog.mk>
