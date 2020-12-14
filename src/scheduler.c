/*
 * Copyright (c) 2020 Matthias Pressfreund
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

#define HAS_DATAMAX(ibuf)	ibuf->datamax < CONF_NO_DATAMAX
#define HAS_TIMEOUT(ibuf)	ibuf->timeout < CONF_NO_TIMEOUT

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
static __dead void
		 shutdown_scheduler(void);

extern struct config	*conf;

int		 sched_cfd, sched_ifd;
pid_t		 sched_pid;
struct clientq	 cltq;
struct config	*nconf = NULL;
struct kevcb	 expire_handler;

static struct inbufq	 inbq;
static int		 kqfd;

static struct client *
evtimer_client(void)
{
	struct client	*first = TAILQ_FIRST(&cltq);

	return (first == NULL || timespec_isinfinite(&first->to) ?
	    NULL : first);
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
	struct client		*clt;
	struct pfaddrlistq	 addq, delq;
	struct clientq		 cqc, dcq;
	struct kevent		 kev;
	struct target		*tgt;
	struct crange		*self;
	struct socket		*sock;

	if ((clt = evtimer_client()) != NULL)
		EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER, EV_DELETE,
		    0, 0, NULL);

	SIMPLEQ_INIT(&addq);
	SIMPLEQ_INIT(&delq);
	TAILQ_INIT(&cqc);
	TAILQ_INIT(&dcq);

	TAILQ_CONCAT(&cqc, &cltq, clients);

	while ((clt = TAILQ_FIRST(&cqc)) != NULL) {
		TAILQ_REMOVE(&cqc, clt, clients);
		clt->tgt = find_target(&nc->ctargets, clt->tgt->name);
		if (bind_table(clt, &addq, &delq))
			sort_client_desc(clt);
		else
			TAILQ_INSERT_TAIL(&dcq, clt, clients);
	}

	apply_pfaddrlists(&addq, &delq);

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

int
drop_clients(struct crangeq *crq, struct ptrq *tpq)
{
	struct ptr	*tp;
	struct crange	*cr;
	struct client	*clt, *nc, *first;
	struct caddrq	 caq;
	int		 cnt;
	char		*age;
	struct pfresult	 pfres;
	struct kevent	 kev;
	struct timespec	 ts;

	SIMPLEQ_INIT(&caq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tpq, tp, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(crq, cr, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		SIMPLEQ_INSERT_TAIL(&caq, &clt->addr, caddrs);
		pfexec(&caq, &pfres, "delete\n%s", clt->tbl->name);

		GET_TIME(&ts);
		timespecsub(&ts, &clt->ts, &ts);
		age = hrage(&ts);
		print_ts_log("%s[%s]:[%s]:(%dx:%s) ",
		    pfres.ndel > 0 ? ">>> Deleted " : "",
		    clt->astr, clt->tgt->name, clt->cnt, age);
		free(age);

		if (pfres.ndel > 0)
			print_log("from { %s } and ", clt->tbl->name);

		TAILQ_REMOVE(&cltq, clt, clients);
		free(clt);
		print_log("dropped.\n");
		cnt++;
	}

	if (first == NULL && (clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);

	return (cnt);
}

int
drop_clients_r(struct crangeq *crq, struct ptrq *tpq)
{
	struct ptr		*tp;
	struct crange		*cr;
	struct client		*clt, *nc, *first;
	struct pfaddrlistq	 delq;
	struct clientq		 dcq;
	int			 cnt;
	struct kevent		 kev;

	SIMPLEQ_INIT(&delq);
	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tpq, tp, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(crq, cr, cranges,
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
		append_client(&delq, clt);
		TAILQ_INSERT_TAIL(&dcq, clt, clients);
		cnt++;
	}

	apply_pfaddrlists(NULL, &delq);

	while ((clt = TAILQ_FIRST(&dcq)) != NULL) {
		TAILQ_REMOVE(&dcq, clt, clients);
		free(clt);
	}

	if (first == NULL && (clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);

	return (cnt);
}

int
expire_clients(struct crangeq *crq, struct ptrq *tpq)
{
	struct ptr	*tp;
	struct crange	*cr;
	struct client	*clt, *nc, *first;
	struct caddrq	 caq;
	struct clientq	 dcq;
	int		 cnt;
	char		*age;
	struct pfresult	 pfres;
	struct kevent	 kev;
	struct timespec	 ts;

	SIMPLEQ_INIT(&caq);
	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (clt->exp)
			continue;
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tpq, tp, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(crq, cr, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		if (clt == first) {
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
			first = NULL;
		}

		SIMPLEQ_INSERT_TAIL(&caq, &clt->addr, caddrs);
		pfexec(&caq, &pfres, "delete\n%s", clt->tbl->name);

		GET_TIME(&ts);
		if (timespec_isinfinite(&clt->tgt->drop))
			clt->to = TIMESPEC_INFINITE;
		else
			timespecadd(&ts, &clt->tgt->drop, &clt->to);
		clt->exp = 1;
		timespecsub(&ts, &clt->ts, &ts);
		age = hrage(&ts);
		print_ts_log("%sDeleted [%s]:[%s]:(%dx:%s)",
		    pfres.ndel > 0 ? ">>> " : "",
		    clt->astr, clt->tgt->name, clt->cnt, age);
		free(age);

		if (pfres.ndel > 0)
			print_log(" from { %s }", clt->tbl->name);
		print_log(".\n");

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

int
expire_clients_r(struct crangeq *crq, struct ptrq *tpq)
{
	struct ptr		*tp;
	struct crange		*cr;
	struct client		*clt, *nc, *first;
	struct pfaddrlistq	 delq;
	struct clientq		 dcq;
	int			 cnt;
	struct kevent		 kev;
	struct timespec		 ts;

	TAILQ_INIT(&dcq);
	cnt = 0;

	first = evtimer_client();

	TAILQ_FOREACH_SAFE(clt, &cltq, clients, nc) {
		if (clt->exp )
			continue;
		if (!SIMPLEQ_EMPTY(tpq)) {
			SIMPLEQ_MATCH(tpq, tp, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!SIMPLEQ_EMPTY(crq)) {
			SIMPLEQ_MATCH(crq, cr, cranges,
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

	SIMPLEQ_INIT(&delq);

	while ((clt = TAILQ_FIRST(&dcq)) != NULL) {
		TAILQ_REMOVE(&dcq, clt, clients);

		GET_TIME(&ts);
		if (timespec_isinfinite(&clt->tgt->drop))
			clt->to = TIMESPEC_INFINITE;
		else
			timespecadd(&ts, &clt->tgt->drop, &clt->to);
		clt->exp = 1;

		sort_client_desc(clt);
		append_client(&delq, clt);
	}

	apply_pfaddrlists(NULL, &delq);

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

	WRITE(sched_cfd, &n, sizeof(n));
}

static struct config *
recv_conf(void)
{

#define CHECK_NEXTITEM					\
	READ(sched_cfd, &mt, sizeof(mt));		\
	if (mt == QUEUE_ENDITEMS)			\
		break;					\
	if (mt != QUEUE_NEXTITEM)			\
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
	case UPDATE_LOGFD:
		recv_logfd(sched_cfd);
		break;
	case DELETE_LOGFD:
		if (logfd != -1) {
			close(logfd);
			logfd = -1;
		}
		break;
	case CHECK_TARGETS:
		check_targets();
		break;
	case UPDATE_CONFIG:
		nconf = recv_conf();
		break;
	case SET_VERBOSE:
		READ(sched_cfd, &v, sizeof(v));
		log_setverbose(v);
		break;
	default:
		FATALX("invalid message type (%d)", mt);
	}
	mt = ACK;
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
	static const char	 nak[] = "NAK\n";

	unsigned long	 kevid = kev->ident;
	struct inbuf	*ibuf = kev->udata;
	char		 buf[BUFSIZ], *data;
	ssize_t		 nr;
	struct target	*tgt;
	struct socket	*sock;
	enum msgtype	 mt;

	if (kev->filter == EVFILT_TIMER) {
		log_warnx("read on target [%s%s] timed out", ibuf->tgtname,
		    ibuf->sockid);
		EV_MOD(kqfd, kev, kevid, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		if (HAS_TIMEOUT(ibuf))
			EV_MOD(kqfd, kev, kevid, EVFILT_TIMER, EV_DELETE, 0, 0,
			    NULL);
		send(ibuf->datafd, nak, sizeof(nak), MSG_NOSIGNAL);
		close(ibuf->datafd);
		goto remove;
	}
	/* EVFILT_READ */
	if ((nr = read(ibuf->datafd, buf, sizeof(buf) - 1)) == -1) {
		if (errno != EIO && errno != ENOTCONN)
			FATAL("read");
		log_warn("read on target [%s%s] failed", ibuf->tgtname,
		    ibuf->sockid);
		EV_MOD(kqfd, kev, kevid, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		if (HAS_TIMEOUT(ibuf))
			EV_MOD(kqfd, kev, kevid, EVFILT_TIMER, EV_DELETE, 0, 0,
			    NULL);
		send(ibuf->datafd, nak, sizeof(nak), MSG_NOSIGNAL);
		close(ibuf->datafd);
		goto remove;
	}
	if (nr <= 0)
		goto eof;

	buf[nr] = '\0';
	ibuf->nr += nr;
	if (HAS_DATAMAX(ibuf) && ibuf->nr > ibuf->datamax) {
		log_warnx("read on target [%s%s] exceeded size limit (%zu)",
		    ibuf->tgtname, ibuf->sockid, ibuf->datamax);
		EV_MOD(kqfd, kev, kevid, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		if (HAS_TIMEOUT(ibuf))
			EV_MOD(kqfd, kev, kevid, EVFILT_TIMER, EV_DELETE, 0, 0,
			    NULL);
		send(ibuf->datafd, nak, sizeof(nak), MSG_NOSIGNAL);
		close(ibuf->datafd);
		goto remove;
	}
	if (asprintf(&data, "%s%s", ibuf->data, buf) == -1)
		FATAL("asprintf");
	free(ibuf->data);
	ibuf->data = data;
	if (buf[nr - 1] != '\0')
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

remove:
	TAILQ_REMOVE(&inbq, ibuf, inbufs);

	if (*ibuf->tgtname != '\0') {
		if ((tgt = find_target(&conf->ctargets,
		    ibuf->tgtname)) == NULL)
			FATALX("could find target [%s]", ibuf->tgtname);
		sock = SIMPLEQ_FIRST(&tgt->datasocks);
		while (sock != NULL && strncmp(sock->id, ibuf->sockid,
		    sizeof(sock->id)))
			sock = SIMPLEQ_NEXT(sock, sockets);
		if (sock == NULL)
			FATALX("could not find socket [%s]", ibuf->sockid);
	} else
		sock = &conf->ctrlsock;

	mt = INBUF_DONE;
	WRITE(sock->ctrlfd, &mt, sizeof(mt));
	/* wait for reply */
	READ(sock->ctrlfd, &mt, sizeof(mt));
	if (mt != ACK)
		FATALX("invalid message type (%d)", mt);

	free(ibuf->data);
	free(ibuf);
}

static void
handle_expire(struct kevent *kev)
{
	struct client	*clt = (struct client *)kev->ident;
	struct table	*tbl = clt->tbl;
	struct caddrq	 caq;
	int		 exp, drop;
	struct pfresult	 pfres;
	char		*age;
	struct timespec	 ts;

	GET_TIME(&ts);

	EV_MOD(kqfd, kev, kev->ident, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);

	SIMPLEQ_INIT(&caq);
	memset(&pfres, 0, sizeof(pfres));

	TAILQ_REMOVE(&cltq, clt, clients);

	exp = !clt->exp;
	drop = !exp || (timespeccmp(&tbl->expire, &tbl->drop, ==) &&
	    !timespec_isinfinite(&tbl->drop));

	if (exp) {
		SIMPLEQ_INSERT_TAIL(&caq, &clt->addr, caddrs);
		pfexec(&caq, &pfres, "delete\n%s", tbl->name);

		if (timespec_isinfinite(&tbl->drop))
			clt->to = TIMESPEC_INFINITE;
		else
			timespecadd(&clt->ts, &tbl->drop, &clt->to);
		clt->exp = 1;
	}

	timespecsub(&ts, &clt->ts, &ts);
	age = hrage(&ts);
	print_ts_log("%s%s[%s]:[%s]:(%dx:%s)", pfres.ndel > 0 ? ">>> " : "",
	    exp ? "Deleted " : "", clt->astr, clt->tgt->name, clt->cnt, age);
	free(age);

	if (exp) {
		if (pfres.ndel > 0)
			print_log(" from { %s }", tbl->name);
		if (drop)
			print_log(" and");
	}
	if (drop)
		print_log(" dropped");

	print_log(".\n");

	if (drop)
		free(clt);
	else
		sort_client_desc(clt);

	if ((clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, kev, clt, &expire_handler);
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

	READ(sched_cfd, &mt, sizeof(mt));
	if (mt == UPDATE_CONFIG) {
		conf = recv_conf();
		mt = ACK;
	} else
		mt = NAK;
	WRITE(sched_cfd, &mt, sizeof(mt));

	TAILQ_INIT(&cltq);
	TAILQ_INIT(&inbq);

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

	expire_handler = (struct kevcb){ &handle_expire, NULL };
	if ((clt = evtimer_client()) != NULL)
		evtimer_start(kqfd, &kev, clt, &expire_handler);
	signal_handler = (struct kevcb){ &handle_signal, NULL };
	EV_MOD(kqfd, &kev, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0,
	    &signal_handler);
	ctrl_handler = (struct kevcb){ &handle_ctrl, NULL };
	EV_MOD(kqfd, &kev, sched_cfd, EVFILT_READ, EV_ADD, 0, 0,
	    &ctrl_handler);
	inbfd_handler = (struct kevcb){ &handle_inbfd, NULL };
	EV_MOD(kqfd, &kev, sched_ifd, EVFILT_READ, EV_ADD, 0, 0,
	    &inbfd_handler);
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
bind_table(struct client *clt, struct pfaddrlistq *addq,
    struct pfaddrlistq *delq)
{
	struct table	*tbl;
	struct timespec	 ts;

	tbl = SIMPLEQ_FIRST(&clt->tgt->cascade);
	while (tbl != NULL && tbl->hits > 0 && tbl->hits < clt->cnt)
		tbl = SIMPLEQ_NEXT(tbl, tables);
	if (tbl == NULL)
		FATALX("open cascade");

	if (clt->tbl != NULL && strcmp(tbl->name, clt->tbl->name))
		append_client(delq, clt);

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

	if (clt->exp == 0)
		append_client(addq, clt);
	else
		append_client(delq, clt);

	return (clt->exp != -1);
}

void
append_client(struct pfaddrlistq *pfalq, struct client *clt)
{
	struct pfaddrlist	*pfal = SIMPLEQ_FIRST(pfalq);

	while (pfal != NULL && strcmp(pfal->tblname, clt->tbl->name))
		pfal = SIMPLEQ_NEXT(pfal, pfaddrlists);
	if (pfal == NULL) {
		MALLOC(pfal, sizeof(*pfal));
		if (strlcpy(pfal->tblname, clt->tbl->name,
		    sizeof(pfal->tblname)) >= sizeof(pfal->tblname))
			FATALX("table name '%s' too long", clt->tbl->name);
		SIMPLEQ_INIT(&pfal->addrq);
		SIMPLEQ_INSERT_TAIL(pfalq, pfal, pfaddrlists);
	}
	SIMPLEQ_INSERT_TAIL(&pfal->addrq, &clt->addr, caddrs);
}

void
apply_pfaddrlists(struct pfaddrlistq *addq, struct pfaddrlistq *delq)
{
	struct pfaddrlist	*pfal;
	struct pfresult		 pfres;

	if (addq == NULL)
		goto del;

	while ((pfal = SIMPLEQ_FIRST(addq)) != NULL) {
		if (!SIMPLEQ_EMPTY(&pfal->addrq)) {
			pfexec(&pfal->addrq, &pfres, "add\n%s", pfal->tblname);
			if (pfres.nadd > 0)
				print_ts_log(">>> Added %d address%s to "
				    "{ %s }.\n", pfres.nadd,
				    pfres.nadd != 1 ? "es" : "",
				    pfal->tblname);
		}
		SIMPLEQ_REMOVE_HEAD(addq, pfaddrlists);
		free(pfal);
	}
del:
	if (delq == NULL)
		return;

	while ((pfal = SIMPLEQ_FIRST(delq)) != NULL) {
		if (!SIMPLEQ_EMPTY(&pfal->addrq)) {
			pfexec(&pfal->addrq, &pfres, "delete\n%s",
			    pfal->tblname);
			if (pfres.ndel > 0)
				print_ts_log(">>> Deleted %d address%s from "
				    "{ %s }.\n", pfres.ndel,
				    pfres.ndel != 1 ? "es" : "",
				    pfal->tblname);
		}
		SIMPLEQ_REMOVE_HEAD(delq, pfaddrlists);
		free(pfal);
	}
}

static __dead void
shutdown_scheduler(void)
{
	extern int	 privfd;

	struct target		*tgt;
	int			 c;
	struct pfaddrlistq	 delq;
	struct client		*clt;
	enum msgtype		 mt;

	if (conf == NULL || SIMPLEQ_EMPTY(&conf->ctargets))
		goto end;

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
		SIMPLEQ_INIT(&delq);
		TAILQ_FOREACH(clt, &cltq, clients)
			if (!clt->exp)
				append_client(&delq, clt);
		if (!SIMPLEQ_EMPTY(&delq)) {
			print_ts_log("Unloading client addresses ...\n");
			apply_pfaddrlists(NULL, &delq);
		}
	}

end:
	mt = SHUTDOWN_MAIN;
	WRITE(privfd, &mt, sizeof(mt));
	exit(0);
}
