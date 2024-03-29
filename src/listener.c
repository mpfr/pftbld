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

#define FLAG_SRVSOCK_CCNTLOG	0x01

#define CADDR_TO_CRANGE(r, a)						\
	do {								\
		(r)->first = (r)->last =				\
		    *(union inaddr *)&(a)->pfaddr.pfra_u;		\
		(r)->af = (a)->pfaddr.pfra_af;				\
		(void)strlcpy((r)->str, (a)->str, sizeof((r)->str));	\
		(void)strlcat((r)->str,					\
		    (r)->af == AF_INET ? "/32" :			\
		    (r)->af == AF_INET6 ? "/128" : "",			\
		    sizeof((r)->str));					\
	} while (0)

#define TIME_TO_STR(str, ts)						\
	do {								\
		struct timespec	 _ts = *ts;				\
		struct tm	*_tm;					\
		if ((_tm = localtime(&_ts.tv_sec)) == NULL)		\
			FATALX("localtime failed");			\
		if (strftime(str, sizeof(str), TS_FMT, _tm) == 0)	\
			FATALX("strftime overflow");			\
	} while (0)

static void	 handle_ctrl(struct kevent *);
static void	 handle_srvsock(struct kevent *);
static struct crange
		*check_cranges(struct crangeq *, struct caddr *);
static struct ptr
		*check_keyterms(struct ptrq *, const char *);
static char	*enq_target_address_params(char *, char *, size_t,
		    struct ptrq *, struct crangeq *);
static void	 free_target_address_queues(struct crangeq *, struct ptrq *);
static int	 perform_ctrl_config(struct statfd *, char *, char *, size_t);
static int	 perform_ctrl_delete(struct statfd *, char *, char *, size_t,
		    unsigned int (*)(struct crangeq *, struct ptrq *),
		    unsigned int (*)(struct crangeq *, struct ptrq *),
		    const char *);
static int	 perform_ctrl_dump(struct statfd *, char *, char *, size_t);
static int	 perform_ctrl_list(struct statfd *, char *, char *, size_t);
static int	 perform_ctrl_save(struct statfd *, char *, char *, size_t);
static int	 perform_ctrl_selfexclude(struct statfd *, char *, char *,
		    size_t);
static int	 perform_ctrl_status(struct statfd *, char *, char *, size_t);
static int	 perform_ctrl_verbose(struct statfd *, char *, char *, size_t);

extern int		 logfd, sched_ifd;
extern struct config	*conf;
extern struct clientq	 cltq;
extern struct kevcb	 expire_handler;

static int		 ccnt, backlog;
static uint8_t		 flags;
static struct inbuf	 ibuftmpl;

static void
handle_ctrl(struct kevent *kev)
{
	int		 v, ctrlfd;
	enum msgtype	 mt;

	if (kev->flags & EV_EOF)
		FATALX("connection closed unexpectedly");

	ctrlfd = kev->ident;
	RECV(ctrlfd, &mt, sizeof(mt));
	switch (mt) {
	case MSG_UPDATE_LOGFD:
		recv_logfd(ctrlfd);
		break;
	case MSG_DELETE_LOGFD:
		if (logfd != -1) {
			close(logfd);
			logfd = -1;
		}
		break;
	case MSG_SET_VERBOSE:
		RECV(ctrlfd, &v, sizeof(v));
		log_setverbose(v);
		break;
	case MSG_INBUF_DONE:
		ccnt--;
		break;
	default:
		FATALX_MSGTYPE(mt);
	}
	mt = MSG_ACK;
	SEND(ctrlfd, &mt, sizeof(mt));
}

static void
handle_srvsock(struct kevent *kev)
{
	int	 datafd;
	pid_t	 pid;

	if (ccnt > backlog) {
		if ((flags & FLAG_SRVSOCK_CCNTLOG) == 0) {
			log_warnx("read on target [%s%s] exceeded backlog "
			    "limit (%d)", ibuftmpl.tgtname, ibuftmpl.sockid,
			    backlog);
			flags |= FLAG_SRVSOCK_CCNTLOG;
		}
		NANONAP;
		return;
	}
	flags &= ~FLAG_SRVSOCK_CCNTLOG;

	if ((datafd = accept(kev->ident, NULL, NULL)) == -1) {
		if (errno == ECONNABORTED)
			return;

		FATAL("accept");
	}

	ccnt++;

	if ((pid = fork()) == -1)
		FATAL("fork");

	if (pid != 0) { /* parent */
		close(datafd);
		return;
	}
	/* child */
	if (pledge("stdio sendfd", NULL) == -1)
		FATAL("pledge");

	while (send_fd(datafd, &ibuftmpl, sizeof(ibuftmpl), sched_ifd) == -1)
		NANONAP;

	_exit(0);
}

__dead void
listener(int argc, char *argv[])
{
	int			 debug, verbose;
	char			*tgtname, *sockpath, *sockid, *ptitle;
	uid_t			 owner;
	gid_t			 group;
	mode_t			 mode;
	int			 ctrlfd, kqfd, srvsockfd;
	struct sockaddr_un	 ssa_un;
	struct kevent		 kev;
	struct kevcb		 ctrl_handler, srvsock_handler;

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_DFL);

	ETOI(debug, ENV_DEBUG);
	ETOI(verbose, ENV_VERBOSE);
	log_init(argv[1], debug, verbose);

	ETOI(logfd, ENV_LOGFD);
	ETOI(ctrlfd, ENV_CTRLFD);
	ETOI(sched_ifd, ENV_INBFD);

	tgtname = argv[2];
	sockid = argv[3];
	sockpath = argv[4];
	STOLL(owner, argv[5]);
	STOLL(group, argv[6]);
	STOI(mode, argv[7]);
	STOI(backlog, argv[8]);
	STOLL(ibuftmpl.datamax, argv[9]);
	STOLL(ibuftmpl.timeout, argv[10]);

	if (*tgtname != '\0')
		ASPRINTF(&ptitle, "data-listener[%s%s]", tgtname, sockid);
	else
		STRDUP(ptitle, "control-listener");
	setproctitle("%s", ptitle);
	free(ptitle);

	if ((srvsockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		FATAL("socket");

	if (unlink(sockpath) == -1 && errno != ENOENT)
		FATAL("unlink(%s)", sockpath);

	memset(&ssa_un, 0, sizeof(ssa_un));
	ssa_un.sun_family = AF_UNIX;
	(void)strlcpy(ssa_un.sun_path, sockpath, sizeof(ssa_un.sun_path));
	if (bind(srvsockfd, (struct sockaddr *)&ssa_un, sizeof(ssa_un)) == -1)
		FATAL("bind(%s)", sockpath);
	if (chown(sockpath, owner, group) == -1)
		FATAL("chown(%s, %u, %u)", sockpath, owner, group);
	if (chmod(sockpath, mode) == -1)
		FATAL("chmod(%s, %04o)", sockpath, mode);

	drop_priv();

	if (listen(srvsockfd, backlog) == -1)
		FATAL("listen");

	ccnt = 0;
	flags = 0;

	(void)strlcpy(ibuftmpl.tgtname, tgtname, sizeof(ibuftmpl.tgtname));
	(void)strlcpy(ibuftmpl.sockid, sockid, sizeof(ibuftmpl.sockid));
	ibuftmpl.nr = 0;

	if ((kqfd = kqueue()) == -1)
		FATAL("kqueue");

	ctrl_handler = (struct kevcb){ &handle_ctrl, NULL };
	EV_MOD(kqfd, &kev, ctrlfd, EVFILT_READ, EV_ADD, 0, 0, &ctrl_handler);
	srvsock_handler = (struct kevcb){ &handle_srvsock, NULL };
	EV_MOD(kqfd, &kev, srvsockfd, EVFILT_READ, EV_ADD, 0, 0,
	    &srvsock_handler);
	memset(&kev, 0, sizeof(kev));

	if (pledge("stdio unix sendfd recvfd proc", NULL) == -1)
		FATAL("pledge");

	while (kevent(kqfd, NULL, 0, &kev, 1, NULL) != -1)
		KEVENT_HANDLE(&kev);
	FATAL("kevent");
}

void
fork_listener(struct socket *sockcfg, char *tgtname)
{
	extern const struct procfunc	 process[];
	extern char			*__progname;

	int	 cfd[2];
	pid_t	 pid;
	char	*argv[12];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, cfd) == -1)
		FATAL("socketpair");

	if ((pid = fork()) == -1)
		FATAL("fork");

	if (pid != 0) { /* parent */
		sockcfg->pid = pid;
		sockcfg->ctrlfd = cfd[0];
		close(cfd[1]);
		return;
	}
	/* child */
	ITOE(ENV_LOGFD, logfd);
	FDTOE(ENV_CTRLFD, cfd[1]);
	FDTOE(ENV_INBFD, sched_ifd);

	argv[0] = process[PROC_LISTENER].name;
	argv[1] = __progname;
	argv[2] = tgtname;
	argv[3] = sockcfg->id;
	argv[4] = sockcfg->path;
	LLTOS(argv[5], (long long)sockcfg->owner);
	LLTOS(argv[6], (long long)sockcfg->group);
	ITOS(argv[7], sockcfg->mode);
	ITOS(argv[8], sockcfg->backlog != CONF_NO_BACKLOG ?
	    sockcfg->backlog : 0);
	LLTOS(argv[9], (long long)sockcfg->datamax);
	LLTOS(argv[10], sockcfg->timeout);
	argv[11] = NULL;

	execvp(__progname, argv);
	FATAL("execvp");
}

static struct crange *
check_cranges(struct crangeq *crq, struct caddr *addr)
{
	struct crange	*cr;

	STAILQ_MATCH(cr, crq, cranges, addr_inrange(cr, addr));

	return (cr);
}

static struct ptr *
check_keyterms(struct ptrq *ktq, const char *buf)
{
	struct ptr	*kt;

	STAILQ_MATCH(kt, ktq, ptrs, strstr(buf, kt->p) != NULL);

	return (kt);
}

void
proc_data(struct inbuf *ibuf, int kqfd)
{
	const char		 ack[] = REPLY_ACK, nak[] = REPLY_NAK;
	int			 datafd = ibuf->datafd;
	struct target		*tgt;
	char			*tgtname, *sockid, *data, *age;
	struct caddr		 addr;
	struct ptr		*pt;
	struct idlewatch	*iw;
	struct socket		*sock;
	struct crangeq		 crq;
	struct ptrq		 tpq;
	struct crange		*cr;
	struct client		*clt, *first;
	struct timespec		 now, tsdiff;
	struct table		*tbl;
	ssize_t			 datalen;
	unsigned int		 clthits;
	struct pfcmd		 cmd;
	struct pfresult		 pfres;
	struct kevent		 kev;

	if ((data = strchr(ibuf->data, '\n')) != NULL)
		*data = '\0';
	memset(&addr, 0, sizeof(addr));
	if (parse_addr(&addr, ibuf->data) == -1) {
		log_warnx("ignored invalid address (%s)", ibuf->data);
		rsend(datafd, nak, sizeof(nak));
		close(datafd);
		return;
	}
	if (data != NULL)
		*data = '\n';

	tgtname = ibuf->tgtname;
	sockid = ibuf->sockid;
	data = ibuf->data;
	datalen = ibuf->nr;

	if ((tgt = find_target_byname(&conf->ctargets, tgtname)) == NULL)
		FATALX("invalid target [%s]", tgtname);

	if ((sock = find_socket_byid(&tgt->datasocks, sockid)) == NULL)
		FATALX("invalid socket [%s]", sockid);

	iw = NULL;

	if ((pt = check_keyterms(&tgt->inclkeyterms, data)) != NULL ||
	    (pt = check_keyterms(&conf->inclkeyterms, data)) != NULL) {
		iw = request_idlewatch(&addr, tgtname, sockid, sock->action);
		if (iw->cnt == 0)
			ASPRINTF(&iw->data, "included keyterm '%s' ",
			    (char *)pt->p);
		goto chkaddr;
	}

	if ((pt = check_keyterms(&tgt->exclkeyterms, data)) != NULL ||
	    (pt = check_keyterms(&conf->exclkeyterms, data)) != NULL) {
		iw = request_idlewatch(&addr, tgtname, sockid, sock->action);
		if (iw->cnt == 0) {
			ASPRINTF(&iw->data, "keyterm '%s'", (char *)pt->p);
			print_ts_log("Ignored excluded %s :: [%s%s] <- [%s]",
			    iw->data, tgtname, sockid,
			    replace(data, "\n", '\0'));
			append_data_log(data, datalen);
			GET_TIME(&iw->ts);
		}
		start_idlewatch(iw, tgt);
		goto end;
	}

chkaddr:
	if ((cr = check_cranges(&tgt->inclcranges, &addr)) != NULL ||
	    (cr = check_cranges(&conf->inclcranges, &addr)) != NULL) {
		if (iw != NULL) /* already has include keyterm match */
			goto next;

		iw = request_idlewatch(&addr, tgtname, sockid, sock->action);
		if (iw->cnt == 0) {
			if (addrvals_cmp(&cr->first, &cr->last, cr->af))
				ASPRINTF(&iw->data, "included network <%s> ",
				    cr->str);
			else
				ASPRINTF(&iw->data, "included address ");
		}
		goto next;
	}

	if ((cr = check_cranges(&tgt->exclcranges, &addr)) != NULL ||
	    (cr = check_cranges(&conf->exclcranges, &addr)) != NULL) {
		if (iw != NULL) /* override include keyterms match */
			cancel_idlewatch(iw);
		iw = request_idlewatch(&addr, tgtname, sockid, sock->action);
		if (iw->cnt == 0) {
			replace(data, "\n", '\0');
			if (addrvals_cmp(&cr->first, &cr->last, cr->af))
				ASPRINTF(&iw->data, "network <%s>", cr->str);
			else
				ASPRINTF(&iw->data, "address");
			print_ts_log("Ignored excluded %s :: [%s%s] <- [%s]",
			    iw->data, tgtname, sockid, data);
			append_data_log(data, datalen);
			GET_TIME(&iw->ts);
		}
		start_idlewatch(iw, tgt);
		goto end;
	}

	if (iw == NULL)
		iw = request_idlewatch(&addr, tgtname, sockid, sock->action);

next:
	TAILQ_FOREACH(clt, &cltq, clients)
		if (clt->tgt == tgt && !addrs_cmp(&clt->addr, &addr))
			break;

	if (sock->action != ACTION_ADD) {
		if (iw->cnt > 0) {
			start_idlewatch(iw, tgt);
			goto end;
		}

		print_ts_log("%s %s:: [%s%s] <- [%s]",
		    ACTION_TO_CSTR(sock->action), iw->data ? iw->data : "",
		    tgtname, sockid, replace(data, "\n", '\0'));
		append_data_log(data, datalen);
		free(iw->data);
		iw->data = NULL;

		if (clt == NULL) {
			print_ts_log("Hmm... [%s]:[%s] is unknown and hence "
			    "cannot be %s.\n", addr.str, tgtname,
			    ACTION_TO_LPSTR(sock->action));
			flush_idlewatches(&addr, tgtname);
			GET_TIME(&iw->ts);
			start_idlewatch(iw, tgt);
			goto end;
		}

		STAILQ_INIT(&crq);
		MALLOC(cr, sizeof(*cr));
		CADDR_TO_CRANGE(cr, &addr);
		STAILQ_INSERT_TAIL(&crq, cr, cranges);
		STAILQ_INIT(&tpq);
		MALLOC(pt, sizeof(*pt));
		pt->p = tgt;
		STAILQ_INSERT_TAIL(&tpq, pt, ptrs);
		switch (sock->action) {
		case ACTION_DELETE:
			switch (expire_clients(&crq, &tpq)) {
			case 0:
				GET_TIME(&tsdiff);
				timespecsub(&tsdiff, &clt->ts, &tsdiff);
				age = hrage(&tsdiff);
				print_ts_log("Hmm... [%s]:[%s]:(%ux:%s) not "
				    "found in { %s }.\n", addr.str, tgtname,
				    clt->hits, age, clt->tbl->name);
				free(age);
				/* FALLTHROUGH */
			case 1:
				break;
			default:
				FATALX("delete failed on [%s]:[%s]", addr.str,
				    tgtname);
			}
			break;
		case ACTION_DROP:
			if (drop_clients(&crq, &tpq) == 0)
				FATALX("drop failed on [%s]:[%s]", addr.str,
				    tgtname);
			break;
		default:
			FATALX("invalid action (%d)", sock->action);
		}
		free_target_address_queues(&crq, &tpq);
		GET_TIME(&iw->ts);
		start_idlewatch(iw, tgt);
		goto end;
	}

	/* ACTION_ADD */

	if (iw->cnt > 0) {
		start_idlewatch(iw, tgt);
		goto end;
	}

	if ((first = TAILQ_FIRST(&cltq)) != NULL &&
	    timespec_isinfinite(&first->to))
		first = NULL;

	if (clt == NULL) {
		CALLOC(clt, 1, sizeof(*clt));
		clt->addr = addr;
		clt->tgt = tgt;
		DPRINTF("new client (%s, %s) created", clt->addr.str, tgtname);
	} else {
		DPRINTF("found enqueued client (%s, %s, %d)", clt->addr.str,
		    tgtname, clt->hits);
		TAILQ_REMOVE(&cltq, clt, clients);
	}

	print_ts_log("Add %s:: [%s%s] <- [%s]", iw->data ? iw->data : "",
	    tgtname, sockid, replace(data, "\n", '\0'));
	append_data_log(data, datalen);
	free(iw->data);
	iw->data = NULL;

	clthits = ++clt->hits;

	tbl = STAILQ_FIRST(&clt->tgt->cascade);
	while (tbl != NULL && tbl->hits > 0 && clthits > tbl->hits)
		tbl = STAILQ_NEXT(tbl, tables);
	if (tbl == NULL)
		FATALX("open cascade");

	if (clthits > tgt->skip) {
		PFCMD_INIT(&cmd, PFCMD_ADD, tbl->name, tbl->flags);
		STAILQ_INSERT_TAIL(&cmd.addrq, &clt->addr, caddrs);
		cmd.addrcnt = 1;
		pfexec(&pfres, &cmd);
		print_ts_log("%s [%s]:[%s]:(%ux",
		    pfres.nadd ? ">>> Added" : "Renewed", clt->addr.str,
		    tgtname, clthits);
	} else
		print_ts_log("Skipped (%u/%u", clthits, tgt->skip);

	GET_TIME(&now);

	if (clthits > 1) {
		timespecsub(&now, &clt->ts, &tsdiff);
		age = hrage(&tsdiff);
		print_log(":%s", age);
		free(age);
	}

	clt->tbl = tbl;
	clt->ts = now;

	if (clthits > tgt->skip) {
		print_log(") %s { %s }", pfres.nadd ? "to" : "from",
		    tbl->name);

		clt->exp = 0;
		if (timespec_isinfinite(&tbl->expire))
			clt->to = TIMESPEC_INFINITE;
		else {
			timespecadd(&now, &tbl->expire, &clt->to);
			age = hrage(&tbl->expire);
			print_log(" for %s", age);
			free(age);
		}

		if (pfres.nkill || pfres.snkill) {
			print_log(" and killed ");

			if (pfres.nkill)
				print_log("%lu state%s", pfres.nkill,
				    pfres.nkill != 1 ? "s" : "");

			if (pfres.snkill)
				print_log("%s%lu node%s",
				    pfres.nkill ? " plus " : "",
				    pfres.snkill, pfres.snkill != 1 ? "s" : "");
		}
	} else {
		print_log(") [%s]:[%s]", clt->addr.str, tgtname);

		if (clthits == 1) {
			clt->exp = 1;
			if (timespec_isinfinite(&tbl->drop))
				clt->to = TIMESPEC_INFINITE;
			else
				timespecadd(&clt->ts, &tbl->drop, &clt->to);
		}
	}

	print_log(".\n");

	sort_client_asc(clt);

	flush_idlewatches(&addr, tgtname);
	GET_TIME(&iw->ts);
	start_idlewatch(iw, tgt);

	if (clt == TAILQ_FIRST(&cltq)) { /* client is new first */
		if (first != NULL)
			EV_MOD(kqfd, &kev, (unsigned long)first, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
		if (!timespec_isinfinite(&clt->to)) {
			timespecsub(&clt->to, &now, &tsdiff);
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_ADD, 0, TIMESPEC_TO_MSEC(&tsdiff),
			    &expire_handler);
		}
	} else if (clt == first) { /* client was first but no longer is */
		if (!timespec_isinfinite(&clt->to))
			EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
		first = TAILQ_FIRST(&cltq);
		if (!timespec_isinfinite(&first->to)) {
			timespecsub(&first->to, &now, &tsdiff);
			EV_MOD(kqfd, &kev, (unsigned long)first, EVFILT_TIMER,
			    EV_ADD, 0, TIMESPEC_TO_MSEC(&tsdiff),
			    &expire_handler);
		}
	}

end:
	rsend(datafd, ack, sizeof(ack));
	close(datafd);
}

static char *
enq_target_address_params(char *arg, char *data, size_t datalen,
    struct ptrq *tpq, struct crangeq *crq)
{
	struct target	*tgt;
	struct ptr	*tp;
	struct crange	*cr;

	do {
		if ((tgt = find_target_byname(&conf->ctargets, arg)) != NULL) {
			MALLOC(tp, sizeof(*tp));
			tp->p = tgt;
			STAILQ_INSERT_TAIL(tpq, tp, ptrs);
		} else if (crq != NULL && (cr = parse_crange(arg)) != NULL)
			STAILQ_INSERT_TAIL(crq, cr, cranges);
		else
			break;
	} while ((arg = shift(arg, data, datalen)) != NULL);

	return (arg);
}

static void
free_target_address_queues(struct crangeq *crq, struct ptrq *tpq)
{
	struct ptr	*tp;
	struct crange	*cr;

	if (crq != NULL)
		while ((cr = STAILQ_FIRST(crq)) != NULL) {
			STAILQ_REMOVE_HEAD(crq, cranges);
			free(cr);
		}

	if (tpq != NULL)
		while ((tp = STAILQ_FIRST(tpq)) != NULL) {
			STAILQ_REMOVE_HEAD(tpq, ptrs);
			free(tp);
		}
}

void
proc_ctrl(struct inbuf *ibuf)
{
	struct statfd	*sfd;
	char		*data = ibuf->data, *arg;
	size_t		 datalen = ibuf->nr;
	int		 status;
#if DEBUG
	char		*buf;

	STRDUP(buf, data);
	DPRINTF("received control command: '%s'(%zu)", replace(buf, "\n", ','),
	    datalen);
	free(buf);
#endif

	sfd = create_statfd(ibuf->datafd);
	arg = shift(replace(data, "\n", '\0'), data, datalen);

	if (!strcmp("config", data))
		status = perform_ctrl_config(sfd, arg, data, datalen);
	else if (!strcmp("drop", data))
		status = perform_ctrl_delete(sfd, arg, data, datalen,
		    &drop_clients, &drop_clients_r, "dropped");
	else if (!strcmp("dump", data))
		status = perform_ctrl_dump(sfd, arg, data, datalen);
	else if (!strcmp("expire", data))
		status = perform_ctrl_delete(sfd, arg, data, datalen,
		    &expire_clients, &expire_clients_r, "expired");
	else if (!strcmp("list", data))
		status = perform_ctrl_list(sfd, arg, data, datalen);
	else if (!strcmp("save", data))
		status = perform_ctrl_save(sfd, arg, data, datalen);
	else if (!strcmp("self-exclude", data))
		status = perform_ctrl_selfexclude(sfd, arg, data, datalen);
	else if (!strcmp("status", data))
		status = perform_ctrl_status(sfd, arg, data, datalen);
	else if (!strcmp("verbose", data))
		status = perform_ctrl_verbose(sfd, arg, data, datalen);
	else {
		msg_send(sfd, "Unknown command.\n");
		status = 0;
	}

	if (status)
		msg_send(sfd, "Syntax error.\n");

	close(sfd->fd);
	free(sfd);
}

static int
perform_ctrl_config(struct statfd *sfd, char *arg, char *data, size_t datalen)
{
	extern int	 privfd;

	enum msgtype	 mt;

	if (shift(arg, data, datalen) != NULL)
		return (1);

	if (!strcmp("print", arg))
		print_conf(sfd);
	else if (!strcmp("reload", arg)) {
		mt = MSG_CONF_RELOAD;
		SEND(privfd, &mt, sizeof(mt));
		/* wait for reply */
		RECV(privfd, &mt, sizeof(mt));
		msg_send(sfd, mt == MSG_ACK ? "Initiated.\n" : "Failed.\n");
	} else
		return (1);

	return (0);
}

static int
perform_ctrl_delete(struct statfd *sfd, char *arg, char *data, size_t datalen,
    unsigned int (*func)(struct crangeq *, struct ptrq *),
    unsigned int (*func_r)(struct crangeq *, struct ptrq *),
    const char *action)
{
	struct ptrq	 tpq;
	struct crangeq	 crq;
	int		 recap;
	unsigned int	 cnt;
	struct ptr	*tgt;
	struct crange	*cr;

	if (arg == NULL)
		return (1);

	if (!strcmp("recap", arg)) {
		if ((arg = shift(arg, data, datalen)) == NULL)
			return (1);

		recap = 1;
	} else
		recap = 0;

	STAILQ_INIT(&tpq);
	STAILQ_INIT(&crq);

	if ((arg = enq_target_address_params(arg, data, datalen, &tpq,
	    &crq)) != NULL) {
		msg_send(sfd, "Invalid address/network or unknown target "
		    "[%s].\n", arg);
		goto end;
	}

	cnt = recap ? func_r(&crq, &tpq) : func(&crq, &tpq);

	if (cnt == 0)
		msg_send(sfd, "No client entries found.\n");
	else {
		if (recap) {
			print_ts_log("%d client entr%s %s from ", cnt,
			    cnt != 1 ? "ies" : "y", action);
			STAILQ_FOREACH(tgt, &tpq, ptrs)
				print_log("[%s]",
				    ((struct target *)tgt->p)->name);
			STAILQ_FOREACH(cr, &crq, cranges)
				print_log("[%s]", cr->str);
			print_log(".\n");
		}
		msg_send(sfd, "%d client entr%s %s.\n", cnt,
		    cnt != 1 ? "ies" : "y", action);
	}

end:
	free_target_address_queues(&crq, &tpq);
	return (0);
}

static int
perform_ctrl_dump(struct statfd *sfd, char *arg, char *data, size_t datalen)
{
	struct ptrq	 tpq;
	struct ptr	*tp;
	struct client	*clt;

	STAILQ_INIT(&tpq);

	if (arg != NULL && (arg = enq_target_address_params(arg, data, datalen,
	    &tpq, NULL)) != NULL) {
		msg_send(sfd, "Unknown target [%s].\n", arg);
		goto end;
	}

	TAILQ_FOREACH(clt, &cltq, clients) {
		if (!STAILQ_EMPTY(&tpq)) {
			STAILQ_MATCH(tp, &tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		msg_send(sfd, "%s %u %lld\n", clt->addr.str, clt->hits,
		    TIMESPEC_SEC_ROUND(&clt->ts));
	}

end:
	free_target_address_queues(NULL, &tpq);
	return (0);
}

static int
perform_ctrl_list(struct statfd *sfd, char *arg, char *data, size_t datalen)
{
	struct ptrq	 tpq, cpq;
	struct crangeq	 crq;
	struct ptr	*tp, *cp;
	struct crange	*cr;
	int		 act = 0, addrs = 0, lim = 0, cnt = 0;
	unsigned int	 hits[2] = { 0 };
	const char	*errstr;
	struct timespec	 now, tsdiff;
	struct client	*clt;
	char		*age, tstr[TS_SIZE], *d;

	if (arg != NULL)
		do {
			if (!strcmp("from", arg)) {
				if ((arg = shift(arg, data, datalen)) != NULL)
					break;
				return (1);
			}
			if (!strcmp("active", arg)) {
				if (act)
					return (1);

				act = 1;
			} else if (!strcmp("inactive", arg)) {
				if (act)
					return (1);

				act = -1;
			} else if (!strcmp("addresses", arg)) {
				if (addrs)
					return (1);

				addrs = 1;
			} else if (!strcmp("hits", arg)) {
				if (hits[0] || hits[1] ||
				    (arg = shift(arg, data, datalen)) == NULL)
					return (1);

				if ((d = strchr(arg, '-')) == NULL)
					hits[0] = hits[1] = strtonum(arg, 1,
					    UINT_MAX, &errstr);
				else if (strlen(arg) > 1) {
					*d = '\0';
					errstr = NULL;
					hits[0] = *arg == '\0' ?
					    1 : strtonum(arg, 1, UINT_MAX,
					    &errstr);
					if (errstr == NULL)
						hits[1] = *(d + 1) == '\0' ?
						    UINT_MAX : strtonum(d + 1,
						    1, UINT_MAX, &errstr);
					*d = '-';
				} else
					return (1);

				if (errstr != NULL || hits[0] > hits[1]) {
					msg_send(sfd, "hits %s.\n",
					    errstr ? errstr : "range invalid");
					return (0);
				}
			} else if (!strcmp("next", arg)) {
				if (lim)
					return (1);

				lim = 1;
			} else if (!strcmp("last", arg)) {
				if (lim)
					return (1);

				lim = -1;
			} else
				return (1);

			if (lim && !cnt) {
				if ((arg = shift(arg, data, datalen)) == NULL)
					return (1);

				cnt = strtonum(arg, 1, INT_MAX, &errstr);
				if (errstr != NULL) {
					msg_send(sfd, "limit %s.\n", errstr);
					return (0);
				}
				lim *= cnt;
			}
		} while ((arg = shift(arg, data, datalen)) != NULL);

	STAILQ_INIT(&tpq);
	STAILQ_INIT(&crq);

	if (arg != NULL && (arg = enq_target_address_params(arg, data, datalen,
	    &tpq, &crq)) != NULL) {
		msg_send(sfd, "Invalid address/network or unknown target "
		    "[%s].\n", arg);
		goto end;
	}

	if (!addrs)
		GET_TIME(&now);

	STAILQ_INIT(&cpq);
	cnt = 0;

	TAILQ_FOREACH_REVERSE(clt, &cltq, clientq, clients) {
		if ((act == 1 && clt->exp) || (act == -1 && !clt->exp))
			continue;
		if (hits[0] && hits[1] &&
		    (clt->hits < hits[0] || clt->hits > hits[1]))
			continue;
		if (!STAILQ_EMPTY(&tpq)) {
			STAILQ_MATCH(tp, &tpq, ptrs, clt->tgt == tp->p);
			if (tp == NULL)
				continue;
		}
		if (!STAILQ_EMPTY(&crq)) {
			STAILQ_MATCH(cr, &crq, cranges,
			    addr_inrange(cr, &clt->addr));
			if (cr == NULL)
				continue;
		}

		MALLOC(cp, sizeof(*cp));
		cp->p = clt;
		STAILQ_INSERT_TAIL(&cpq, cp, ptrs);
		if (lim >= 0)
			cnt++;
	}

	while ((cp = STAILQ_FIRST(&cpq)) != NULL) {
		clt = cp->p;
		STAILQ_REMOVE_HEAD(&cpq, ptrs);
		free(cp);

		if (lim > 0 && cnt > lim) {
			cnt--;
			continue;
		}
		if (lim < 0) {
			if (cnt < -lim)
				cnt++;
			else
				continue;
		}

		if (addrs) {
			msg_send(sfd, "%s\n", clt->addr.str);
			continue;
		}

		timespecsub(&now, &clt->ts, &tsdiff);
		age = hrage(&tsdiff);
		msg_send(sfd, "[%s]:[%s]:(%dx:%s)\n\t", clt->addr.str,
		    clt->tgt->name, clt->hits, age);
		free(age);

		if (timespec_isinfinite(&clt->to)) {
			if (clt->exp)
				msg_send(sfd, "never gets dropped\n");
			else
				msg_send(sfd, "in { %s }, never expires\n",
				    clt->tbl->name);
		} else {
			timespecsub(&clt->to, &now, &tsdiff);
			age = hrage(&tsdiff);
			TIME_TO_STR(tstr, &clt->to);
			if (clt->exp)
				msg_send(sfd, "getting dropped in %s,\n\ton "
				    "[%s]\n", age, tstr);
			else
				msg_send(sfd, "more %s in { %s },\n\tuntil "
				    "[%s]\n", age, clt->tbl->name, tstr);
			free(age);
		}
	}

	if (!addrs) {
		if (cnt == 0)
			msg_send(sfd, "No client entries found.\n");
		else
			msg_send(sfd, "%d client entr%s found.\n", cnt,
			    cnt != 1 ? "ies" : "y");
	}

end:
	free_target_address_queues(&crq, &tpq);
	return (0);
}

static int
perform_ctrl_save(struct statfd *sfd, char *arg, char *data, size_t datalen)
{
	struct ptrq	 tpq;
	struct target	*tgt;
	struct ptr	*tp;
	int		 cnt;

	STAILQ_INIT(&tpq);

	if (arg == NULL)
		STAILQ_FOREACH(tgt, &conf->ctargets, targets) {
			MALLOC(tp, sizeof(*tp));
			tp->p = tgt;
			STAILQ_INSERT_TAIL(&tpq, tp, ptrs);
		}
	else if ((arg = enq_target_address_params(arg, data, datalen, &tpq,
	    NULL)) != NULL) {
		msg_send(sfd, "Unknown target [%s].\n", arg);
		goto end;
	}

	STAILQ_FOREACH(tp, &tpq, ptrs) {
		tgt = tp->p;
		if (*tgt->persist == '\0')
			msg_send(sfd, "No persist file specified for [%s].\n",
			    tgt->name);

		if ((cnt = save(tgt)) != -1)
			msg_send(sfd, "%d client entr%s written for [%s].\n",
			    cnt, cnt != 1 ? "ies" : "y", tgt->name);
		else
			msg_send(sfd, "Saving failed for [%s]. Check the "
			    "system log.\n", tgt->name);
	}

end:
	free_target_address_queues(NULL, &tpq);
	return (0);
}

static int
perform_ctrl_selfexclude(struct statfd *sfd, char *arg, char *data,
    size_t datalen)
{
	struct crange	*r, *r2;

	if (shift(arg, data, datalen) != NULL)
		return (1);

	r = STAILQ_FIRST(&conf->exclcranges);
	if (arg == NULL) {
		if (*r->str != '\0')
			msg_send(sfd, "[%s]\n", r->str);
		else
			msg_send(sfd, "None.\n");
		return (0);
	}
	if (!strcmp("remove", arg)) {
		STAILQ_REMOVE_HEAD(&conf->exclcranges, cranges);
		memset(r, 0, sizeof(*r));
		STAILQ_INSERT_HEAD(&conf->exclcranges, r, cranges);
		print_ts_log("Removed self exclude.\n");
		msg_send(sfd, "Done.\n");
		return (0);
	}
	if ((r2 = parse_crange(arg)) == NULL) {
		msg_send(sfd, "Invalid address/network.\n");
		return (0);
	}
	if (cranges_eq(r, r2)) {
		free(r2);
		msg_send(sfd, "Ditto.\n");
		return (0);
	}
	STAILQ_REMOVE_HEAD(&conf->exclcranges, cranges);
	free(r);
	STAILQ_INSERT_HEAD(&conf->exclcranges, r2, cranges);
	print_ts_log("Updated self exclude to [%s].\n", r2->str);
	msg_send(sfd, "Done.\n");

	return (0);
}

static int
perform_ctrl_status(struct statfd *sfd, char *arg, char *data, size_t datalen)
{
	struct crange	*r;
	int		*cnt[2], c;
	struct client	*clt;
	struct target	*tgt;
	char		*age, tstr[TS_SIZE];
	struct timespec	 now, tsdiff;

	if (arg != NULL)
		return (1);

	r = STAILQ_FIRST(&conf->exclcranges);
	msg_send(sfd, "Self-exclude: [%s]\nVerbosity level: %d\n",
	    *r->str != '\0' ? r->str : "N/A", log_getverbose());
	c = 0;
	STAILQ_FOREACH(tgt, &conf->ctargets, targets)
		c++;
	/* at least one target exists => c > 0 here */
	CALLOC(cnt[0], c, sizeof(int));
	CALLOC(cnt[1], c, sizeof(int));
	TAILQ_FOREACH(clt, &cltq, clients) {
		c = 0;
		STAILQ_FOREACH(tgt, &conf->ctargets, targets)
			if (clt->tgt == tgt) {
				cnt[0][c]++;
				if (!clt->exp)
					cnt[1][c]++;
				break;
			} else
				c++;
	}
	c = 0;
	msg_send(sfd, "Client count:");
	STAILQ_FOREACH(tgt, &conf->ctargets, targets) {
		msg_send(sfd, "\n\ttarget [%s]: %d", tgt->name, cnt[0][c]);
		if (cnt[1][c])
			msg_send(sfd, " (%d active)", cnt[1][c]);
		c++;
	}
	free(cnt[0]);
	free(cnt[1]);
	clt = TAILQ_FIRST(&cltq);
	if (clt == NULL || timespec_isinfinite(&clt->to)) {
		msg_send(sfd, "\nNo event pending.\n");
		return (0);
	}
	TIME_TO_STR(tstr, &clt->to);
	GET_TIME(&now);
	timespecsub(&now, &clt->ts, &tsdiff);
	age = hrage(&tsdiff);
	msg_send(sfd, "\nNext scheduled event:\n\t[%s]:[%s]:(%dx:%s)\n\t\t",
	    clt->addr.str, clt->tgt->name, clt->hits, age);
	free(age);
	if (clt->exp)
		msg_send(sfd, "getting dropped");
	else
		msg_send(sfd, "expires from { %s }", clt->tbl->name);
	timespecsub(&clt->to, &now, &tsdiff);
	age = hrage(&tsdiff);
	msg_send(sfd, " in %s,\n\t\ton [%s]\n", age, tstr);
	free(age);

	return (0);
}

static int
perform_ctrl_verbose(struct statfd *sfd, char *arg, char *data, size_t datalen)
{
	extern int	 privfd;

	int		 v;
	const char	*errstr;
	enum msgtype	 mt;

	if (shift(arg, data, datalen) != NULL)
		return (1);

	if (arg == NULL) {
		msg_send(sfd, "%d\n", log_getverbose());
		return (0);
	}
	v = strtonum(arg, 0, INT_MAX, &errstr);
	if (errstr != NULL) {
		msg_send(sfd, "Verbosity level %s.\n", errstr);
		return (0);
	}
	log_setverbose(v);
	ITOE(ENV_VERBOSE, v);

	mt = MSG_SET_VERBOSE;
	ISEND(privfd, 2, &mt, sizeof(mt), &v, sizeof(v));
	/* wait for reply */
	RECV(privfd, &mt, sizeof(mt));
	msg_send(sfd, mt == MSG_ACK ? "Done.\n" : "Failed.\n");

	return (0);
}
