/*
 * Copyright (c) 2020, 2021 Matthias Pressfreund
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

#include <net/if.h>

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
static void	 handle_ignore(struct kevent *);
static void	 append_client(struct pfcmdq *, struct client *, enum pfcmdid);
static __dead void
		 shutdown_scheduler(void);

extern struct config	*conf;

int		 sched_cfd, sched_ifd;
pid_t		 sched_pid;
struct clientq	 cltq;
struct config	*nconf = NULL;
struct kevcb	 expire_handler, ignore_handler;

static struct inbufq	 inbq;
static int		 kqfd;
static struct ignoreq	 ignq;

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
	struct pfcmdq	 cmdq;
	struct clientq	 cqc, dcq;
	struct kevent	 kev;
	struct target	*tgt;
	struct crange	*self;
	struct socket	*sock;

	if ((clt = evtimer_client()) != NULL)
		EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER, EV_DELETE,
		    0, 0, NULL);

	SIMPLEQ_INIT(&cmdq);
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

	close(conf->ctrlsock.ctrlfd);
	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets)
			close(sock->ctrlfd);

	self = SIMPLEQ_FIRST(&conf->exclcranges);
	SIMPLEQ_REMOVE_HEAD(&conf->exclcranges, cranges);
	SIMPLEQ_INSERT_HEAD(&nc->exclcranges, self, cranges);

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

	PFCMD_INIT(&cmd, PFCMD_DELETE, NULL, 0);
	cmd.addrcnt = 1;

	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(cr, crq, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		cmd.tblname = clt->tbl->name;
		SIMPLEQ_INSERT_TAIL(&cmd.addrq, &clt->addr, caddrs);
		pfexec(&pfres, &cmd);

		TAILQ_REMOVE(&cltq, clt, clients);

		GET_TIME(&ts);
		timespecsub(&ts, &clt->ts, &ts);
		age = hrage(&ts);
		if (pfres.ndel > 0)
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

	SIMPLEQ_INIT(&cmdq);
	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(cr, crq, cranges,
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

	PFCMD_INIT(&cmd, PFCMD_DELETE, NULL, 0);
	cmd.addrcnt = 1;

	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (clt->exp)
			continue;
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(cr, crq, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		cmd.tblname = clt->tbl->name;
		SIMPLEQ_INSERT_TAIL(&cmd.addrq, &clt->addr, caddrs);
		pfexec(&pfres, &cmd);

		GET_TIME(&ts);
		if (timespec_isinfinite(&clt->tgt->drop))
			clt->to = TIMESPEC_INFINITE;
		else
			timespecadd(&ts, &clt->tgt->drop, &clt->to);
		clt->exp = 1;
		if (pfres.ndel > 0) {
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

	SIMPLEQ_INIT(&cmdq);
	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (clt->exp )
			continue;
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tp, tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(cr, crq, cranges,
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

	READ(sched_cfd, &len, sizeof(len));
	MALLOC(buf, len);
	READ(sched_cfd, buf, len);

	(void)replace(buf, "\n", '\0');
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

	WRITE(sched_cfd, &n, sizeof(n));
}

static struct config *
recv_conf(void)
{

#define CHECK_NEXTITEM					\
	READ(sched_cfd, &mt, sizeof(mt));		\
	if (mt == MSG_QUEUE_ENDITEMS)			\
		break;					\
	if (mt != MSG_QUEUE_NEXTITEM)			\
		FATALX("invalid message type (%d)", mt)

	struct config	*nc;
	enum msgtype	 mt;
	size_t		 n;
	struct socket	*sock;
	struct target	*tgt;
	struct crange	*cr;
	struct ptr	*kt;
	struct table	*tbl;

	MALLOC(nc, sizeof(*nc));
	while ((nc->ctrlsock.ctrlfd = recv_fd(nc, sizeof(*nc),
	    sched_cfd)) == -1)
		NANONAP;

	SIMPLEQ_INIT(&nc->ctargets);

	while (1) {
		CHECK_NEXTITEM;

		MALLOC(tgt, sizeof(*tgt));
		READ(sched_cfd, tgt, sizeof(*tgt));
		SIMPLEQ_INSERT_TAIL(&nc->ctargets, tgt, targets);

		SIMPLEQ_INIT(&tgt->datasocks);

		while (1) {
			CHECK_NEXTITEM;

			MALLOC(sock, sizeof(*sock));
			while ((sock->ctrlfd = recv_fd(sock, sizeof(*sock),
			    sched_cfd)) == -1)
				NANONAP;
			SIMPLEQ_INSERT_TAIL(&tgt->datasocks, sock, sockets);
		}

		SIMPLEQ_INIT(&tgt->exclcranges);

		while (1) {
			CHECK_NEXTITEM;

			MALLOC(cr, sizeof(*cr));
			READ(sched_cfd, cr, sizeof(*cr));
			SIMPLEQ_INSERT_TAIL(&tgt->exclcranges, cr, cranges);
		}

		SIMPLEQ_INIT(&tgt->exclkeyterms);

		while (1) {
			CHECK_NEXTITEM;

			MALLOC(kt, sizeof(*kt));
			READ2(sched_cfd, kt, sizeof(*kt), &n, sizeof(n));
			MALLOC(kt->p, n);
			READ(sched_cfd, kt->p, n);
			SIMPLEQ_INSERT_TAIL(&tgt->exclkeyterms, kt, ptrs);
		}

		SIMPLEQ_INIT(&tgt->cascade);

		while (1) {
			CHECK_NEXTITEM;

			MALLOC(tbl, sizeof(*tbl));
			READ(sched_cfd, tbl, sizeof(*tbl));
			SIMPLEQ_INSERT_TAIL(&tgt->cascade, tbl, tables);
		}
	}

	SIMPLEQ_INIT(&nc->exclcranges);

	while (1) {
		CHECK_NEXTITEM;

		MALLOC(cr, sizeof(*cr));
		READ(sched_cfd, cr, sizeof(*cr));
		SIMPLEQ_INSERT_TAIL(&nc->exclcranges, cr, cranges);
	}

	SIMPLEQ_INIT(&nc->exclkeyterms);

	while (1) {
		CHECK_NEXTITEM;

		MALLOC(kt, sizeof(*kt));
		READ2(sched_cfd, kt, sizeof(*kt), &n, sizeof(n));
		MALLOC(kt->p, n);
		READ(sched_cfd, kt->p, n);
		SIMPLEQ_INSERT_TAIL(&nc->exclkeyterms, kt, ptrs);
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

	READ(sched_cfd, &mt, sizeof(mt));
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
		READ(sched_cfd, &v, sizeof(v));
		log_setverbose(v);
		break;
	default:
		FATALX("invalid message type (%d)", mt);
	}
	mt = MSG_ACK;
	WRITE(sched_cfd, &mt, sizeof(mt));
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
	if ((nr = read(ibuf->datafd, buf, sizeof(buf))) == -1) {
		if (errno != EIO && errno != ENOTCONN)
			FATAL("read");
		log_warn("read on target [%s%s] failed (%d)", ibuf->tgtname,
		    ibuf->sockid, errno);
		goto abort;
	}
	if (nr <= 0)
		goto eof;

	inr = ibuf->nr + nr;
	if (HAS_DATAMAX(ibuf) && inr > ibuf->datamax) {
		log_warnx("read on target [%s%s] exceeded size limit (%zd)",
		    ibuf->tgtname, ibuf->sockid, ibuf->datamax);
		goto abort;
	}
	if ((data = realloc(ibuf->data, inr + 1)) == NULL)
		FATAL("realloc");
	(void)memcpy(&data[ibuf->nr], buf, nr);
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
	send(ibuf->datafd, nak, sizeof(nak), MSG_NOSIGNAL);
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
	WRITE(sock->ctrlfd, &mt, sizeof(mt));
	/* wait for reply */
	READ(sock->ctrlfd, &mt, sizeof(mt));
	if (mt != MSG_ACK)
		FATALX("invalid message type (%d)", mt);

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
		SIMPLEQ_INSERT_TAIL(&cmd.addrq, &clt->addr, caddrs);
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
	    exp ? pfres.ndel > 0 ? ">>> Deleted" : "Hmm..." : "Dropped",
	    clt->addr.str, clt->tgt->name, clt->hits, age);
	free(age);

	if (exp) {
		print_log(" %s { %s }",
		    pfres.ndel > 0 ? "from" : "not found in", tbl->name);
		if (drop)
			print_log(pfres.ndel > 0 ?
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
handle_ignore(struct kevent *kev)
{
	struct ignore	*ign;
	struct timespec	 ts, *timeout = (struct timespec *)kev->udata;

	EV_MOD(kqfd, kev, kev->ident, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	ign = (struct ignore *)kev->ident;
	TAILQ_REMOVE(&ignq, ign, ignores);

	if (--ign->cnt == 0)
		goto end;

	GET_TIME(&ts);
	timespecsub(&ts, &ign->ts, &ts);
	if (timeout != NULL)
		timespecsub(&ts, timeout, &ts);
	print_ts_log("[%lld ms] Ignored %u ", TIMESPEC_TO_MSEC(&ts), ign->cnt);
	if (ign->data == NULL)
		print_log("duplicate %s request%s",
		    ACTION_TO_LSTR(*(enum pfaction *)ign->ident),
		    ign->cnt == 1 ? "" : "s");
	else
		print_log("more time%s excluded %s", ign->cnt == 1 ? "" : "s",
		    ign->data);
	print_log(" :: [%s%s] <- [%s].\n", ign->tgtname, ign->sockid,
	    ign->addr.str);

end:
	free(ign->tgtname);
	free(ign->sockid);
	free(ign->data);
	free(ign);
}

struct ignore *
request_ignore(struct caddr *addr, char *tgtname, char *sockid, void *ident)
{
	struct ignore	*ign;
	struct kevent	 kev;

	TAILQ_FOREACH(ign, &ignq, ignores)
		if (ign->ident == ident && !addrs_cmp(&ign->addr, addr) &&
		    !strcmp(ign->tgtname, tgtname) && !strcmp(ign->sockid,
		    sockid)) {
			EV_MOD(kqfd, &kev, (unsigned long)ign, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			return (ign);
		}

	MALLOC(ign, sizeof(*ign));
	ign->ident = ident;
	ign->addr = *addr;
	STRDUP(ign->tgtname, tgtname);
	STRDUP(ign->sockid, sockid);
	ign->data = NULL;
	ign->cnt = 0;
	TAILQ_INSERT_TAIL(&ignq, ign, ignores);
	return (ign);
}

void
start_ignore(struct ignore *ign)
{
	struct kevent	 kev;

	ign->cnt++;
	EV_MOD(kqfd, &kev, (unsigned long)ign, EVFILT_TIMER, EV_ADD, 0,
	    IGNORE_TIMEOUT, &ignore_handler);
}

__dead void
scheduler(int argc, char *argv[])
{
	static struct timespec	 ign_to = { 0, IGNORE_TIMEOUT * 1000000L };

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

	READ(sched_cfd, &mt, sizeof(mt));
	if (mt == MSG_UPDATE_CONFIG) {
		conf = recv_conf();
		mt = MSG_ACK;
	} else
		mt = MSG_NAK;
	WRITE(sched_cfd, &mt, sizeof(mt));

	TAILQ_INIT(&cltq);
	TAILQ_INIT(&inbq);
	TAILQ_INIT(&ignq);

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		if (*tgt->persist == '\0') {
			log_debug("no persist file for target [%s]",
			    tgt->name);
			continue;
		}
		print_ts_log("Restoring data for [%s] ...\n", tgt->name);
		if ((c = load(tgt)) == -1)
			log_debug("persist file %s for target [%s] not found",
			    tgt->persist, tgt->name);
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
	ignore_handler = (struct kevcb){ &handle_ignore, &ign_to };
	memset(&kev, 0, sizeof(kev));

	if (pledge("recvfd sendfd unix stdio", NULL) == -1)
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

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctrlfd) == -1 ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, inbfd) == -1)
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

	tbl = SIMPLEQ_FIRST(&clt->tgt->cascade);
	while (tbl != NULL && tbl->hits > 0 && tbl->hits < clt->hits)
		tbl = SIMPLEQ_NEXT(tbl, tables);
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
	struct pfcmd	*cmd = SIMPLEQ_FIRST(cmdq);

	while (cmd != NULL && (cmd->id != cmdid ||
	    strcmp(cmd->tblname, clt->tbl->name)))
		cmd = SIMPLEQ_NEXT(cmd, pfcmds);
	if (cmd == NULL) {
		MALLOC(cmd, sizeof(*cmd));
		PFCMD_INIT(cmd, cmdid, clt->tbl->name, 0);
		SIMPLEQ_INSERT_TAIL(cmdq, cmd, pfcmds);
		cmd->addrcnt = 0;
	}
	SIMPLEQ_INSERT_TAIL(&cmd->addrq, &clt->addr, caddrs);
	cmd->addrcnt++;
}

void
apply_pfcmds(struct pfcmdq *cmdq)
{
	struct pfcmd	*cmd;
	struct pfresult	 pfres;

	while ((cmd = SIMPLEQ_FIRST(cmdq)) != NULL) {
		if (cmd->addrcnt > 0) {
			pfexec(&pfres, cmd);
			switch (cmd->id) {
			case PFCMD_ADD:
				if (pfres.nadd > 0)
					print_ts_log(">>> Added %d address%s"
					    " to { %s }.\n", pfres.nadd,
					    pfres.nadd != 1 ? "es" : "",
					    cmd->tblname);
				break;
			case PFCMD_DELETE:
				if (pfres.ndel > 0)
					print_ts_log(">>> Deleted %d address%s"
					    " from { %s }.\n", pfres.ndel,
					    pfres.ndel != 1 ? "es" : "",
					    cmd->tblname);
				break;
			default:
				FATAL("invalid cmd id (%d)", cmd->id);
			}
		}
		SIMPLEQ_REMOVE_HEAD(cmdq, pfcmds);
		free(cmd);
	}
}

static __dead void
shutdown_scheduler(void)
{
	extern int	 privfd;

	struct ignore	*ign;
	struct kevent	 kev;
	struct target	*tgt;
	int		 c;
	struct pfcmdq	 cmdq;
	struct client	*clt;
	enum msgtype	 mt;

	if (conf == NULL || SIMPLEQ_EMPTY(&conf->ctargets))
		goto end;

	kev.udata = NULL;
	while ((ign = TAILQ_FIRST(&ignq)) != NULL) {
		kev.ident = (unsigned long)ign;
		handle_ignore(&kev);
	}

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		if (*tgt->persist == '\0')
			log_debug("no persist file for target [%s]",
			    tgt->name);
		else if ((c = save(tgt)) == -1)
			log_warn("failed saving client addresses for target "
			    "[%s]", tgt->name);
		else
			print_ts_log("%d client address%s saved for [%s].\n",
			    c, c != 1 ? "es" : "", tgt->name);
	}

	if (conf->flags & FLAG_GLOBAL_UNLOAD) {
		SIMPLEQ_INIT(&cmdq);
		TAILQ_FOREACH(clt, &cltq, clients)
			if (!clt->exp)
				append_client(&cmdq, clt, PFCMD_DELETE);
		if (!SIMPLEQ_EMPTY(&cmdq)) {
			print_ts_log("Unloading client addresses ...\n");
			apply_pfcmds(&cmdq);
		}
	}

end:
	mt = MSG_SHUTDOWN_MAIN;
	WRITE(privfd, &mt, sizeof(mt));
	exit(0);
}
