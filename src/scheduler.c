/*
 * Copyright (c) 2020 - 2024 Matthias Pressfreund
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "pftbld.h"

#define HAS_DATAMAX(ibuf)	(ibuf->datamax != CONF_NO_DATAMAX)
#define HAS_TIMEOUT(ibuf)	(ibuf->timeout != CONF_NO_TIMEOUT)

static struct client
		*evtimer_client(void);
static void	 evtimer_start(int, struct kevent *, struct client *,
		    struct kevcb *);
static void	 update_conf(struct config *);
static void	 check_targets(void);
static struct config
		*recv_conf(void);
static void	 handle_signal(struct kevent *);
static void	 handle_ctrl(struct kevent *);
static void	 handle_inbfd(struct kevent *);
static void	 handle_inbuf(struct kevent *);
static void	 handle_expire(struct kevent *);
static void	 handle_idle(struct kevent *);
static void	 flushall_idlewatches(void);
static void	 append_client(struct pfcmdq *, struct client *, enum pfcmdid);
static __dead void
		 shutdown_scheduler(void);

extern struct config	*conf;

int		 sched_cfd, sched_ifd;
pid_t		 sched_pid;
struct clientq	 cltq;
struct config	*nconf = NULL;
struct kevcb	 expire_handler;

static struct inbufq		 inbq;
static int			 kqfd;
static struct idlewatchq	 iwq;

static struct client *
evtimer_client(void)
{
	struct client	*clt = TAILQ_FIRST(&cltq);

	return (clt == NULL || timespec_isinfinite(&clt->to) ? NULL : clt);
}

static void
evtimer_start(int fd, struct kevent *kev, struct client *clt,
    struct kevcb *handler)
{
	struct timespec	 ts;

	GET_TIME(&ts);
	timespecsub(&clt->to, &ts, &ts);
	if (ts.tv_sec < 0 || ts.tv_nsec < 0)
		timespecclear(&ts);
	EV_MOD(fd, kev, (unsigned long)clt, EVFILT_TIMER, EV_ADD, 0,
	    TIMESPEC_TO_MSEC(&ts), handler);
}

static void
update_conf(struct config *nc)
{
	struct client	*clt;
	struct kevent	 kev;
	struct pfcmdq	 cmdq;
	struct clientq	 cqc, dcq;
	struct target	*tgt;
	struct crange	*self;
	struct socket	*sock;

	if ((clt = evtimer_client()) != NULL)
		EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER, EV_DELETE,
		    0, 0, NULL);

	STAILQ_INIT(&cmdq);
	TAILQ_INIT(&cqc);
	TAILQ_INIT(&dcq);

	TAILQ_CONCAT(&cqc, &cltq, clients);

	while ((clt = TAILQ_FIRST(&cqc)) != NULL) {
		TAILQ_REMOVE(&cqc, clt, clients);
		clt->tgt = find_target_byname(&nc->ctargets, clt->tgt->name);
		if (bind_table(clt, &cmdq))
			sort_client_desc(clt);
		else
			TAILQ_INSERT_TAIL(&dcq, clt, clients);
	}

	apply_pfcmds(&cmdq);

	while ((clt = TAILQ_FIRST(&dcq)) != NULL) {
		TAILQ_REMOVE(&dcq, clt, clients);
		free(clt);
	}

	if ((clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);

	flushall_idlewatches();

	close(conf->ctrlsock.ctrlfd);
	STAILQ_FOREACH(tgt, &conf->ctargets, targets)
		STAILQ_FOREACH(sock, &tgt->datasocks, sockets)
			close(sock->ctrlfd);

	self = STAILQ_FIRST(&nc->exclcranges);
	STAILQ_REMOVE_HEAD(&nc->exclcranges, cranges);
	free(self);
	self = STAILQ_FIRST(&conf->exclcranges);
	STAILQ_REMOVE_HEAD(&conf->exclcranges, cranges);
	STAILQ_INSERT_HEAD(&nc->exclcranges, self, cranges);

	free_conf(conf);
	conf = nc;
}

void
sort_client_asc(struct client *clt)
{
	struct client	*c;

	c = TAILQ_FIRST(&cltq);
	while (c != NULL && timespeccmp(&clt->to, &c->to, >=))
		c = TAILQ_NEXT(c, clients);

	if (c == NULL)
		TAILQ_INSERT_TAIL(&cltq, clt, clients);
	else
		TAILQ_INSERT_BEFORE(c, clt, clients);
}

void
sort_client_desc(struct client *clt)
{
	struct client	*c;

	c = TAILQ_LAST(&cltq, clientq);
	while (c != NULL && timespeccmp(&clt->to, &c->to, <))
		c = TAILQ_PREV(c, clientq, clients);

	if (c == NULL)
		TAILQ_INSERT_HEAD(&cltq, clt, clients);
	else
		TAILQ_INSERT_AFTER(&cltq, c, clt, clients);
}

unsigned int
drop_clients(struct crangeq *crq, struct ptrq *tpq)
{
	struct pfcmd	 cmd;
	struct ptr	*tp;
	struct crange	*cr;
	struct client	*clt, *nc, *first;
	unsigned int	 cnt;
	char		*age;
	struct pfresult	 pfres;
	struct kevent	 kev;
	struct timespec	 ts;

	cmd.addrcnt = 1;
	cnt = 0;
	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (!STAILQ_EMPTY(tpq)) {
			STAILQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!STAILQ_EMPTY(crq)) {
			STAILQ_MATCH(cr, crq, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		TAILQ_REMOVE(&cltq, clt, clients);
		flush_idlewatches(&clt->addr, clt->tgt->name);

		PFCMD_INIT(&cmd, PFCMD_DELETE, clt->tbl->name, 0);
		STAILQ_INSERT_TAIL(&cmd.addrq, &clt->addr, caddrs);
		pfexec(&pfres, &cmd);

		GET_TIME(&ts);
		timespecsub(&ts, &clt->ts, &ts);
		age = hrage(&ts);
		if (pfres.ndel)
			print_ts_log(">>> Deleted [%s]:[%s]:(%ux:%s) from "
			    "{ %s } and dropped.\n", clt->addr.str,
			    clt->tgt->name, clt->hits, age, clt->tbl->name);
		else
			print_ts_log("Dropped [%s]:[%s]:(%ux:%s).\n",
			    clt->addr.str, clt->tgt->name, clt->hits, age);
		free(age);

		free(clt);
		cnt++;
	}

	if (first == NULL && (clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);

	return (cnt);
}

unsigned int
drop_clients_r(struct crangeq *crq, struct ptrq *tpq)
{
	struct pfcmdq	 cmdq;
	struct clientq	 dcq;
	unsigned int	 cnt;
	struct client	*clt, *nc, *first;
	struct ptr	*tp;
	struct crange	*cr;
	struct kevent	 kev;

	STAILQ_INIT(&cmdq);
	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (!STAILQ_EMPTY(tpq)) {
			STAILQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!STAILQ_EMPTY(crq)) {
			STAILQ_MATCH(cr, crq, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		TAILQ_REMOVE(&cltq, clt, clients);
		flush_idlewatches(&clt->addr, clt->tgt->name);
		append_client(&cmdq, clt, PFCMD_DELETE);
		TAILQ_INSERT_TAIL(&dcq, clt, clients);
		cnt++;
	}

	apply_pfcmds(&cmdq);

	while ((clt = TAILQ_FIRST(&dcq)) != NULL) {
		TAILQ_REMOVE(&dcq, clt, clients);
		free(clt);
	}

	if (first == NULL && (clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);

	return (cnt);
}

unsigned int
expire_clients(struct crangeq *crq, struct ptrq *tpq)
{
	struct pfcmd	 cmd;
	struct ptr	*tp;
	struct crange	*cr;
	struct client	*clt, *nc, *first;
	struct clientq	 dcq;
	unsigned int	 cnt;
	char		*age;
	struct pfresult	 pfres;
	struct kevent	 kev;
	struct timespec	 ts;

	TAILQ_INIT(&dcq);

	cmd.addrcnt = 1;
	cnt = 0;
	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (clt->exp)
			continue;

		if (!STAILQ_EMPTY(tpq)) {
			STAILQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!STAILQ_EMPTY(crq)) {
			STAILQ_MATCH(cr, crq, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		flush_idlewatches(&clt->addr, clt->tgt->name);

		PFCMD_INIT(&cmd, PFCMD_DELETE, clt->tbl->name, 0);
		STAILQ_INSERT_TAIL(&cmd.addrq, &clt->addr, caddrs);
		pfexec(&pfres, &cmd);

		GET_TIME(&ts);
		if (timespec_isinfinite(&clt->tgt->drop))
			clt->to = TIMESPEC_INFINITE;
		else
			timespecadd(&ts, &clt->tgt->drop, &clt->to);
		clt->exp = 1;
		if (pfres.ndel) {
			timespecsub(&ts, &clt->ts, &ts);
			age = hrage(&ts);
			print_ts_log(">>> Deleted [%s]:[%s]:(%ux:%s) from "
			    "{ %s }.\n", clt->addr.str, clt->tgt->name,
			    clt->hits, age, clt->tbl->name);
			free(age);
		}

		TAILQ_REMOVE(&cltq, clt, clients);
		TAILQ_INSERT_TAIL(&dcq, clt, clients);
		cnt++;
	}

	while ((clt = TAILQ_FIRST(&dcq)) != NULL) {
		TAILQ_REMOVE(&dcq, clt, clients);
		sort_client_desc(clt);
	}

	if (first == NULL && (clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);

	return (cnt);
}

unsigned int
expire_clients_r(struct crangeq *crq, struct ptrq *tpq)
{
	struct pfcmdq	 cmdq;
	struct clientq	 dcq;
	unsigned int	 cnt;
	struct client	*clt, *nc, *first;
	struct ptr	*tp;
	struct crange	*cr;
	struct kevent	 kev;
	struct timespec	 ts;

	STAILQ_INIT(&cmdq);
	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (clt->exp )
			continue;

		if (!STAILQ_EMPTY(tpq)) {
			STAILQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!STAILQ_EMPTY(crq)) {
			STAILQ_MATCH(cr, crq, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		TAILQ_REMOVE(&cltq, clt, clients);
		flush_idlewatches(&clt->addr, clt->tgt->name);
		TAILQ_INSERT_TAIL(&dcq, clt, clients);
		cnt++;
	}

	while ((clt = TAILQ_FIRST(&dcq)) != NULL) {
		TAILQ_REMOVE(&dcq, clt, clients);

		GET_TIME(&ts);
		if (timespec_isinfinite(&clt->tgt->drop))
			clt->to = TIMESPEC_INFINITE;
		else
			timespecadd(&ts, &clt->tgt->drop, &clt->to);
		clt->exp = 1;

		sort_client_desc(clt);
		append_client(&cmdq, clt, PFCMD_DELETE);
	}

	apply_pfcmds(&cmdq);

	if (first == NULL && (clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);

	return (cnt);
}

static void
check_targets(void)
{
	size_t		 len;
	int		 n;
	char		*buf, *tgt;
	struct client	*clt;

	RECV(sched_cfd, &len, sizeof(len));
	MALLOC(buf, len);
	RECV(sched_cfd, buf, len);

	replace(buf, "\n", '\0');
	n = 0;
	TAILQ_FOREACH(clt, &cltq, clients) {
		tgt = buf;
		while (strncmp(clt->tgt->name, tgt, sizeof(clt->tgt->name)))
			if ((tgt = shift(tgt, buf, len)) == NULL) {
				n++;
				break;
			}
	}
	free(buf);

	SEND(sched_cfd, &n, sizeof(n));
}

static struct config *
recv_conf(void)
{

#define CHECK_NEXTITEM				\
	RECV(sched_cfd, &mt, sizeof(mt));	\
	if (mt == MSG_QUEUE_ENDITEMS)		\
		break;				\
	if (mt != MSG_QUEUE_NEXTITEM)		\
		FATALX_MSGTYPE(mt)

	struct config	*nc;
	enum msgtype	 mt;
	size_t		 n;
	struct socket	*sock;
	struct target	*tgt;
	struct timespec	*its;
	struct crange	*cr;
	struct ptr	*kt;
	struct table	*tbl;

	MALLOC(nc, sizeof(*nc));
	while ((nc->ctrlsock.ctrlfd = recv_fd(nc, sizeof(*nc),
	    sched_cfd)) == -1)
		NANONAP;

	STAILQ_INIT(&nc->ctargets);

	for (;;) {
		CHECK_NEXTITEM;

		MALLOC(tgt, sizeof(*tgt));
		RECV(sched_cfd, tgt, sizeof(*tgt));
		STAILQ_INSERT_TAIL(&nc->ctargets, tgt, targets);

		/* initialize idle handler */
		MALLOC(its, sizeof(*its));
		MSEC_TO_TIMESPEC(its,
		    tgt->idlemin != CONF_NO_IDLEMIN ? tgt->idlemin : 0);
		tgt->idlehandler = (struct kevcb){ &handle_idle, its };

		STAILQ_INIT(&tgt->datasocks);

		for (;;) {
			CHECK_NEXTITEM;

			MALLOC(sock, sizeof(*sock));
			while ((sock->ctrlfd = recv_fd(sock, sizeof(*sock),
			    sched_cfd)) == -1)
				NANONAP;
			STAILQ_INSERT_TAIL(&tgt->datasocks, sock, sockets);
		}

		STAILQ_INIT(&tgt->exclcranges);

		for (;;) {
			CHECK_NEXTITEM;

			MALLOC(cr, sizeof(*cr));
			RECV(sched_cfd, cr, sizeof(*cr));
			STAILQ_INSERT_TAIL(&tgt->exclcranges, cr, cranges);
		}

		STAILQ_INIT(&tgt->exclkeyterms);

		for (;;) {
			CHECK_NEXTITEM;

			MALLOC(kt, sizeof(*kt));
			IRECV(sched_cfd, 2, kt, sizeof(*kt), &n, sizeof(n));
			MALLOC(kt->p, n);
			RECV(sched_cfd, kt->p, n);
			STAILQ_INSERT_TAIL(&tgt->exclkeyterms, kt, ptrs);
		}

		STAILQ_INIT(&tgt->inclcranges);

		for (;;) {
			CHECK_NEXTITEM;

			MALLOC(cr, sizeof(*cr));
			RECV(sched_cfd, cr, sizeof(*cr));
			STAILQ_INSERT_TAIL(&tgt->inclcranges, cr, cranges);
		}

		STAILQ_INIT(&tgt->inclkeyterms);

		for (;;) {
			CHECK_NEXTITEM;

			MALLOC(kt, sizeof(*kt));
			IRECV(sched_cfd, 2, kt, sizeof(*kt), &n, sizeof(n));
			MALLOC(kt->p, n);
			RECV(sched_cfd, kt->p, n);
			STAILQ_INSERT_TAIL(&tgt->inclkeyterms, kt, ptrs);
		}

		STAILQ_INIT(&tgt->cascade);

		for (;;) {
			CHECK_NEXTITEM;

			MALLOC(tbl, sizeof(*tbl));
			RECV(sched_cfd, tbl, sizeof(*tbl));
			STAILQ_INSERT_TAIL(&tgt->cascade, tbl, tables);
		}
	}

	STAILQ_INIT(&nc->exclcranges);

	for (;;) {
		CHECK_NEXTITEM;

		MALLOC(cr, sizeof(*cr));
		RECV(sched_cfd, cr, sizeof(*cr));
		STAILQ_INSERT_TAIL(&nc->exclcranges, cr, cranges);
	}

	STAILQ_INIT(&nc->exclkeyterms);

	for (;;) {
		CHECK_NEXTITEM;

		MALLOC(kt, sizeof(*kt));
		IRECV(sched_cfd, 2, kt, sizeof(*kt), &n, sizeof(n));
		MALLOC(kt->p, n);
		RECV(sched_cfd, kt->p, n);
		STAILQ_INSERT_TAIL(&nc->exclkeyterms, kt, ptrs);
	}

	STAILQ_INIT(&nc->inclcranges);

	for (;;) {
		CHECK_NEXTITEM;

		MALLOC(cr, sizeof(*cr));
		RECV(sched_cfd, cr, sizeof(*cr));
		STAILQ_INSERT_TAIL(&nc->inclcranges, cr, cranges);
	}

	STAILQ_INIT(&nc->inclkeyterms);

	for (;;) {
		CHECK_NEXTITEM;

		MALLOC(kt, sizeof(*kt));
		IRECV(sched_cfd, 2, kt, sizeof(*kt), &n, sizeof(n));
		MALLOC(kt->p, n);
		RECV(sched_cfd, kt->p, n);
		STAILQ_INSERT_TAIL(&nc->inclkeyterms, kt, ptrs);
	}

#undef CHECK_NEXTITEM

	return (nc);
}

static void
handle_signal(struct kevent *kev)
{
	int	 sig = kev->ident;

	switch (sig) {
	case SIGTERM:
		if (TAILQ_EMPTY(&inbq)) {
			print_ts_log("Shutdown requested.\n");
			shutdown_scheduler();
			/* NOTREACHED */
		}
		if (sched_cfd != -1) {
			EV_MOD(kqfd, kev, sched_cfd, EVFILT_READ, EV_DELETE, 0,
			    0, NULL);
			sched_cfd = -1;
		}
		if (sched_ifd != -1) {
			EV_MOD(kqfd, kev, sched_ifd, EVFILT_READ, EV_DELETE, 0,
			    0, NULL);
			sched_ifd = -1;
		}
		raise(SIGTERM);
		break;
	default:
		FATALX("unexpected signal (%d)", sig);
	}
}

static void
handle_ctrl(struct kevent *kev)
{
	extern int	 logfd;

	enum msgtype	 mt;
	int		 v;

	if (kev->flags & EV_EOF)
		FATALX("connection closed unexpectedly");

	RECV(sched_cfd, &mt, sizeof(mt));
	switch (mt) {
	case MSG_UPDATE_LOGFD:
		recv_logfd(sched_cfd);
		break;
	case MSG_DELETE_LOGFD:
		if (logfd != -1) {
			close(logfd);
			logfd = -1;
		}
		break;
	case MSG_CHECK_TARGETS:
		check_targets();
		break;
	case MSG_UPDATE_CONFIG:
		nconf = recv_conf();
		break;
	case MSG_SET_VERBOSE:
		RECV(sched_cfd, &v, sizeof(v));
		log_setverbose(v);
		break;
	default:
		FATALX_MSGTYPE(mt);
	}
	mt = MSG_ACK;
	SEND(sched_cfd, &mt, sizeof(mt));
}

static void
handle_inbfd(struct kevent *kev)
{
	struct inbuf	*ibuf;

	MALLOC(ibuf, sizeof(*ibuf));

	while ((ibuf->datafd = recv_fd(ibuf, sizeof(*ibuf), sched_ifd)) == -1)
		NANONAP;

	CALLOC(ibuf->data, 1, 1);
	ibuf->handler = (struct kevcb){ &handle_inbuf, ibuf };

	TAILQ_INSERT_TAIL(&inbq, ibuf, inbufs);

	EV_MOD(kqfd, kev, ibuf->datafd, EVFILT_READ, EV_ADD, 0, 0,
	    &ibuf->handler);
	if (HAS_TIMEOUT(ibuf))
		EV_MOD(kqfd, kev, ibuf->datafd, EVFILT_TIMER, EV_ADD, 0,
		    ibuf->timeout, &ibuf->handler);
}

static void
handle_inbuf(struct kevent *kev)
{
	const char	 nak[] = REPLY_NAK;
	unsigned long	 kevid = kev->ident;
	struct inbuf	*ibuf = kev->udata;
	char		 buf[BUFSIZ], *data;
	ssize_t		 nr, inr;
	struct target	*tgt;
	struct socket	*sock;
	enum msgtype	 mt;

	if (kev->filter == EVFILT_TIMER) {
		log_warnx("read on target [%s%s] timed out", ibuf->tgtname,
		    ibuf->sockid);
		goto abort;
	}
	/* EVFILT_READ */
	/* ignore EV_EOF */
	if ((nr = recv(ibuf->datafd, buf, sizeof(buf), 0)) == -1) {
		if (errno != ENOTCONN && errno != ECONNREFUSED)
			FATAL("recv");
		log_warn("read on target [%s%s] failed (%d)", ibuf->tgtname,
		    ibuf->sockid, errno);
		goto abort;
	}
	if (nr == 0)
		goto eof;

	inr = ibuf->nr + nr;
	if (HAS_DATAMAX(ibuf) && inr > ibuf->datamax) {
		log_warnx("read on target [%s%s] exceeded size limit (%zd)",
		    ibuf->tgtname, ibuf->sockid, ibuf->datamax);
		goto abort;
	}
	if ((data = realloc(ibuf->data, inr + 1)) == NULL)
		FATAL("realloc");
	memcpy(&data[ibuf->nr], buf, nr);
	data[inr] = '\0';
	ibuf->data = data;
	ibuf->nr = inr;
	if (buf[--nr] != '\0')
		return;

eof:
	/* EOF */
	EV_MOD(kqfd, kev, kevid, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if (HAS_TIMEOUT(ibuf))
		EV_MOD(kqfd, kev, kevid, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	if (*ibuf->tgtname != '\0')
		proc_data(ibuf, kqfd);
	else
		proc_ctrl(ibuf);

	goto remove;

abort:
	EV_MOD(kqfd, kev, kevid, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if (HAS_TIMEOUT(ibuf))
		EV_MOD(kqfd, kev, kevid, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
	RSEND(ibuf->datafd, nak, sizeof(nak));
	close(ibuf->datafd);

remove:
	TAILQ_REMOVE(&inbq, ibuf, inbufs);

	if (*ibuf->tgtname != '\0') {
		if ((tgt = find_target_byname(&conf->ctargets,
		    ibuf->tgtname)) == NULL)
			FATALX("invalid target [%s]", ibuf->tgtname);
		if ((sock = find_socket_byid(&tgt->datasocks,
		    ibuf->sockid)) == NULL)
			FATALX("invalid socket [%s]", ibuf->sockid);
	} else
		sock = &conf->ctrlsock;

	mt = MSG_INBUF_DONE;
	SEND(sock->ctrlfd, &mt, sizeof(mt));
	/* wait for reply */
	RECV(sock->ctrlfd, &mt, sizeof(mt));
	if (mt != MSG_ACK)
		FATALX_MSGTYPE(mt);

	free(ibuf->data);
	free(ibuf);
}

static void
handle_expire(struct kevent *kev)
{
	struct client	*clt;
	struct table	*tbl;
	struct pfcmd	 cmd;
	int		 exp, drop;
	struct pfresult	 pfres;
	char		*age;
	struct timespec	 ts;

	EV_MOD(kqfd, kev, kev->ident, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	GET_TIME(&ts);

	clt = (struct client *)kev->ident;
	tbl = clt->tbl;

	memset(&pfres, 0, sizeof(pfres));

	TAILQ_REMOVE(&cltq, clt, clients);

	exp = !clt->exp;
	drop = !exp || (timespeccmp(&tbl->expire, &tbl->drop, ==) &&
	    !timespec_isinfinite(&tbl->drop));

	if (exp) {
		PFCMD_INIT(&cmd, PFCMD_DELETE, tbl->name, 0);
		STAILQ_INSERT_TAIL(&cmd.addrq, &clt->addr, caddrs);
		cmd.addrcnt = 1;
		pfexec(&pfres, &cmd);

		if (timespec_isinfinite(&tbl->drop))
			clt->to = TIMESPEC_INFINITE;
		else
			timespecadd(&clt->ts, &tbl->drop, &clt->to);
		clt->exp = 1;
	}

	timespecsub(&ts, &clt->ts, &ts);
	age = hrage(&ts);
	print_ts_log("%s [%s]:[%s]:(%ux:%s)",
	    exp ? pfres.ndel ? ">>> Deleted" : "Hmm..." : "Dropped",
	    clt->addr.str, clt->tgt->name, clt->hits, age);
	free(age);

	if (exp) {
		print_log(" %s { %s }",
		    pfres.ndel ? "from" : "not found in", tbl->name);
		if (drop)
			print_log(pfres.ndel ?
			    " and dropped" : " but dropped anyway");
	}
	print_log(".\n");

	if (drop)
		free(clt);
	else
		sort_client_desc(clt);

	if ((clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, kev, clt, &expire_handler);
}

static void
handle_idle(struct kevent *kev)
{
	struct idlewatch	*iw;
	struct timespec		 ts, *timeout = kev->udata;

	EV_MOD(kqfd, kev, kev->ident, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	iw = (struct idlewatch *)kev->ident;
	TAILQ_REMOVE(&iwq, iw, idlewatches);

	if (--iw->cnt == 0)
		goto end;

	GET_TIME(&ts);
	timespecsub(&ts, &iw->ts, &ts);
	if (timeout != NULL)
		timespecsub(&ts, timeout, &ts);
	print_ts_log("[%lld ms] Ignored %u ", TIMESPEC_TO_MSEC(&ts), iw->cnt);
	if (iw->data == NULL)
		print_log("%s request duplicate%s", ACTION_TO_LSTR(iw->action),
		    iw->cnt == 1 ? "" : "s");
	else
		print_log("more time%s excluded %s", iw->cnt == 1 ? "" : "s",
		    iw->data);
	print_log(" :: [%s%s] <- [%s].\n", iw->tgtname, iw->sockid,
	    iw->addr.str);

end:
	free(iw->tgtname);
	free(iw->sockid);
	free(iw->data);
	free(iw);
}

struct idlewatch *
request_idlewatch(struct caddr *addr, char *tgtname, char *sockid,
    enum pfaction action)
{
	struct idlewatch	*iw;
	struct kevent		 kev;

	TAILQ_FOREACH(iw, &iwq, idlewatches)
		if (iw->action == action &&
		    !addrs_cmp(&iw->addr, addr) &&
		    !strcmp(iw->tgtname, tgtname) &&
		    !strcmp(iw->sockid, sockid)) {
			EV_MOD(kqfd, &kev, (unsigned long)iw, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			return (iw);
		}

	MALLOC(iw, sizeof(*iw));
	iw->addr = *addr;
	STRDUP(iw->tgtname, tgtname);
	STRDUP(iw->sockid, sockid);
	iw->data = NULL;
	iw->action = action;
	iw->cnt = 0;
	TAILQ_INSERT_TAIL(&iwq, iw, idlewatches);
	return (iw);
}

void
start_idlewatch(struct idlewatch *iw, struct target *tgt)
{
	struct kevent	 kev;

	if (tgt->idlemin != CONF_NO_IDLEMIN) {
		iw->cnt++;
		EV_MOD(kqfd, &kev, (unsigned long)iw, EVFILT_TIMER, EV_ADD, 0,
		    tgt->idlemin, &tgt->idlehandler);
	} else
		cancel_idlewatch(iw);
}

void
cancel_idlewatch(struct idlewatch *iw)
{
	struct kevent	 kev;

	if (iw->cnt)
		EV_MOD(kqfd, &kev, (unsigned long)iw, EVFILT_TIMER, EV_DELETE,
		    0, 0, NULL);
	TAILQ_REMOVE(&iwq, iw, idlewatches);
	free(iw->tgtname);
	free(iw->sockid);
	free(iw->data);
	free(iw);
}

void
flush_idlewatches(struct caddr *addr, const char *tgtname)
{
	struct kevent		 kev;
	struct idlewatch	*iw, *tiw;

	kev.udata = NULL;
	TAILQ_FOREACH_SAFE(iw, &iwq, idlewatches, tiw)
		if (iw->cnt && !addrs_cmp(&iw->addr, addr) &&
		    !strcmp(iw->tgtname, tgtname)) {
			kev.ident = (unsigned long)iw;
			handle_idle(&kev);
		}
}

static void
flushall_idlewatches(void)
{
	struct kevent		 kev;
	struct idlewatch	*iw;

	kev.udata = NULL;
	while ((iw = TAILQ_FIRST(&iwq)) != NULL)
		if (iw->cnt) {
			kev.ident = (unsigned long)iw;
			handle_idle(&kev);
		} else
			cancel_idlewatch(iw);
}

__dead void
scheduler(int argc, char *argv[])
{
	extern int	 privfd, logfd;

	int		 debug, verbose, c;
	enum msgtype	 mt;
	struct kevent	 kev;
	struct target	*tgt;
	struct client	*clt;
	struct kevcb	 signal_handler, ctrl_handler, inbfd_handler;

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);

	ETOI(debug, ENV_DEBUG);
	ETOI(verbose, ENV_VERBOSE);
	log_init(argv[1], debug, verbose);
	setproctitle("%s", __func__);

	ETOI(privfd, ENV_PRIVFD);
	ETOI(logfd, ENV_LOGFD);
	ETOI(sched_cfd, ENV_CTRLFD);
	ETOI(sched_ifd, ENV_INBFD);

	RECV(sched_cfd, &mt, sizeof(mt));
	if (mt == MSG_UPDATE_CONFIG) {
		conf = recv_conf();
		mt = MSG_ACK;
	} else
		mt = MSG_NAK;
	SEND(sched_cfd, &mt, sizeof(mt));

	TAILQ_INIT(&cltq);
	TAILQ_INIT(&inbq);
	TAILQ_INIT(&iwq);

	STAILQ_FOREACH(tgt, &conf->ctargets, targets) {
		if (*tgt->persist == '\0') {
			log_debug("no persist file for target [%s]",
			    tgt->name);
			continue;
		}
		print_ts_log("Restoring data for [%s] ...\n", tgt->name);
		if ((c = load(tgt)) == -1)
			print_ts_log("Cancelled. Persist file not yet "
			    "available.\n");
		else
			print_ts_log("%d client address%s loaded.\n", c,
			    c != 1 ? "es" : "");
	}

	drop_priv();

	if ((kqfd = kqueue()) == -1)
		FATAL("kqueue");

	signal_handler = (struct kevcb){ &handle_signal, NULL };
	EV_MOD(kqfd, &kev, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0,
	    &signal_handler);
	ctrl_handler = (struct kevcb){ &handle_ctrl, NULL };
	EV_MOD(kqfd, &kev, sched_cfd, EVFILT_READ, EV_ADD, 0, 0,
	    &ctrl_handler);
	inbfd_handler = (struct kevcb){ &handle_inbfd, NULL };
	EV_MOD(kqfd, &kev, sched_ifd, EVFILT_READ, EV_ADD, 0, 0,
	    &inbfd_handler);
	expire_handler = (struct kevcb){ &handle_expire, NULL };
	if ((clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);
	memset(&kev, 0, sizeof(kev));

	if (pledge("stdio unix recvfd", NULL) == -1)
		FATAL("pledge");

	print_ts_log("Startup succeeded. Listening ...\n");

	while (kevent(kqfd, NULL, 0, &kev, 1, NULL) != -1) {
		KEVENT_HANDLE(&kev);

		if (nconf != NULL) {
			update_conf(nconf);
			nconf = NULL;
			print_ts_log("Configuration successfully reloaded.\n");
		}
	}
	FATAL("kevent");
}

void
fork_scheduler(void)
{
	extern int			 logfd, privfd;
	extern const struct procfunc	 process[];
	extern char			*__progname;

	int	 ctrlfd[2], inbfd[2];
	char	*argv[3];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctrlfd) == -1)
		FATAL("socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, inbfd) == -1)
		FATAL("socketpair");

	if ((sched_pid = fork()) == -1)
		FATAL("fork");

	if (sched_pid != 0) { /* parent */
		sched_cfd = ctrlfd[0];
		close(ctrlfd[1]);
		close(inbfd[0]);
		sched_ifd = inbfd[1];
		return;
	}
	/* child */
	FDTOE(ENV_PRIVFD, privfd);
	ITOE(ENV_LOGFD, logfd);
	FDTOE(ENV_CTRLFD, ctrlfd[1]);
	FDTOE(ENV_INBFD, inbfd[0]);

	argv[0] = process[PROC_SCHEDULER].name;
	argv[1] = __progname;
	argv[2] = NULL;

	execvp(__progname, argv);
	FATAL("execvp");
}

int
bind_table(struct client *clt, struct pfcmdq *cmdq)
{
	struct table	*tbl;
	struct timespec	 ts;

	tbl = STAILQ_FIRST(&clt->tgt->cascade);
	while (tbl != NULL && tbl->hits > 0 && tbl->hits < clt->hits)
		tbl = STAILQ_NEXT(tbl, tables);
	if (tbl == NULL)
		FATALX("open cascade");

	if (clt->tbl != NULL && strcmp(tbl->name, clt->tbl->name))
		append_client(cmdq, clt, PFCMD_DELETE);

	clt->tbl = tbl;

	GET_TIME(&ts);
	timespecsub(&ts, &clt->ts, &ts);

	if (timespec_isinfinite(&tbl->expire)) {
		clt->exp = 0;
		clt->to = TIMESPEC_INFINITE;
	} else if (timespeccmp(&ts, &tbl->expire, <)) {
		clt->exp = 0;
		timespecadd(&clt->ts, &tbl->expire, &clt->to);
	} else if (timespec_isinfinite(&tbl->drop)) {
		clt->exp = 1;
		clt->to = TIMESPEC_INFINITE;
	} else if (timespeccmp(&ts, &tbl->drop, <)) {
		clt->exp = 1;
		timespecadd(&clt->ts, &tbl->drop, &clt->to);
	} else
		clt->exp = -1;

	append_client(cmdq, clt, clt->exp == 0 ? PFCMD_ADD : PFCMD_DELETE);

	return (clt->exp != -1);
}

static void
append_client(struct pfcmdq *cmdq, struct client *clt, enum pfcmdid cmdid)
{
	struct pfcmd	*cmd = STAILQ_FIRST(cmdq);

	while (cmd != NULL && (cmd->id != cmdid ||
	    strcmp(cmd->tblname, clt->tbl->name)))
		cmd = STAILQ_NEXT(cmd, pfcmds);
	if (cmd == NULL) {
		MALLOC(cmd, sizeof(*cmd));
		PFCMD_INIT(cmd, cmdid, clt->tbl->name, 0);
		STAILQ_INSERT_TAIL(cmdq, cmd, pfcmds);
		cmd->addrcnt = 0;
	}
	STAILQ_INSERT_TAIL(&cmd->addrq, &clt->addr, caddrs);
	cmd->addrcnt++;
}

void
apply_pfcmds(struct pfcmdq *cmdq)
{
	struct pfcmd	*cmd;
	struct pfresult	 pfres;

	while ((cmd = STAILQ_FIRST(cmdq)) != NULL) {
		if (cmd->addrcnt > 0) {
			pfexec(&pfres, cmd);
			switch (cmd->id) {
			case PFCMD_ADD:
				if (pfres.nadd)
					print_ts_log(">>> Added %lu address%s"
					    " to { %s }.\n", pfres.nadd,
					    pfres.nadd != 1 ? "es" : "",
					    cmd->tblname);
				break;
			case PFCMD_DELETE:
				if (pfres.ndel)
					print_ts_log(">>> Deleted %lu "
					    "address%s from { %s }.\n",
					    pfres.ndel,
					    pfres.ndel != 1 ? "es" : "",
					    cmd->tblname);
				break;
			default:
				FATAL("invalid cmd id (%d)", cmd->id);
			}
		}
		STAILQ_REMOVE_HEAD(cmdq, pfcmds);
		free(cmd);
	}
}

static __dead void
shutdown_scheduler(void)
{
	extern int	 privfd;

	struct target	*tgt;
	int		 c;
	struct pfcmdq	 cmdq;
	struct client	*clt;
	enum msgtype	 mt;

	if (conf == NULL || STAILQ_EMPTY(&conf->ctargets))
		goto end;

	flushall_idlewatches();

	STAILQ_FOREACH(tgt, &conf->ctargets, targets)
		if (*tgt->persist == '\0')
			log_debug("no persist file for target [%s]",
			    tgt->name);
		else if ((c = save(tgt)) == -1)
			log_warnx("failed saving client addresses for target "
			    "[%s]", tgt->name);
		else
			print_ts_log("%d client address%s saved for [%s].\n",
			    c, c != 1 ? "es" : "", tgt->name);

	if (conf->flags & FLAG_GLOBAL_UNLOAD) {
		STAILQ_INIT(&cmdq);
		TAILQ_FOREACH(clt, &cltq, clients)
			if (!clt->exp)
				append_client(&cmdq, clt, PFCMD_DELETE);
		if (!STAILQ_EMPTY(&cmdq)) {
			print_ts_log("Unloading client addresses ...\n");
			apply_pfcmds(&cmdq);
		}
	}

end:
	mt = MSG_SHUTDOWN_MAIN;
	SEND(privfd, &mt, sizeof(mt));
	exit(0);
}
