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

#include <sys/stat.h>

#include "log.h"
#include "pftbld.h"

#define FLAG_SRVSOCK_CCNTLOG	0x01

static void	 handle_ctrl(struct kevent *);
static void	 handle_srvsock(struct kevent *);
static struct keyterm
		*check_exclkeyterms(struct keytermq *, char *);
static struct crange
		*check_exclcranges(struct crangeq *, struct caddr *);
static int	 perform_ctrl_delete(int, char *, char *, size_t,
		    int (*)(const char *, struct target *),
		    int (*)(const char *, struct target *), const char *);
static int	 perform_ctrl_dump(int, char *, char *, size_t);
static int	 perform_ctrl_list(int, char *, char *, size_t);
static int	 perform_ctrl_reload(int, char *, char *, size_t);
static int	 perform_ctrl_save(int, char *, char *, size_t);
static int	 perform_ctrl_selfexclude(int, char *, char *, size_t);
static int	 perform_ctrl_status(int, char *, char *, size_t);
static int	 perform_ctrl_verbose(int, char *, char *, size_t);

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
	READ(ctrlfd, &mt, sizeof(mt));
	switch (mt) {
	case UPDATE_LOGFD:
		recv_logfd(ctrlfd);
		break;
	case DELETE_LOGFD:
		if (logfd != -1) {
			close(logfd);
			logfd = -1;
		}
		break;
	case SET_VERBOSE:
		READ(ctrlfd, &v, sizeof(v));
		log_setverbose(v);
		break;
	case INBUF_DONE:
		ccnt--;
		break;
	default:
		FATALX("invalid message type (%d)", mt);
	}
	mt = ACK;
	WRITE(ctrlfd, &mt, sizeof(mt));
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
	if (pid == 0) { /* child */
		if (pledge("sendfd stdio", NULL) == -1)
			FATAL("pledge");

		while (send_fd(datafd, &ibuftmpl, sizeof(ibuftmpl),
		    sched_ifd) == -1)
			NANONAP;

		exit(0);
	}
	/* parent */
	close(datafd);
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
	size_t			 datamax;
	time_t			 timeout;
	struct sockaddr_un	 ssa_un;
	struct kevent		 kev;
	struct kevcb		 ctrl_handler, srvsock_handler;

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);

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
	STOLL(datamax, argv[9]);
	STOLL(timeout, argv[10]);

	if (*tgtname != '\0') {
		if (asprintf(&ptitle, "data-listener[%s%s]", tgtname,
		    sockid) == -1)
			FATAL("asprintf");
	} else if ((ptitle = strdup("control-listener")) == NULL)
		FATAL("strdup");
	setproctitle("%s", ptitle);
	free(ptitle);

	if ((srvsockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		FATAL("socket");

	if (unlink(sockpath) == -1 && errno != ENOENT)
		FATAL("unlink(%s)", sockpath);

	memset(&ssa_un, 0, sizeof(ssa_un));
	ssa_un.sun_family = AF_UNIX;
	if (strlcpy(ssa_un.sun_path, sockpath,
	    sizeof(ssa_un.sun_path)) >= sizeof(ssa_un.sun_path))
		FATALX("socket path truncated (%s)", sockpath);
	if (bind(srvsockfd, (struct sockaddr *)&ssa_un, sizeof(ssa_un)) == -1)
		FATAL("bind(%s)", sockpath);
	if (chown(sockpath, owner, group) == -1)
		FATAL("chown(%s, %u, %u)", sockpath, owner, group);
	if (chmod(sockpath, mode) == -1)
		FATAL("chmod(%s, %03o)", sockpath, mode);

	drop_priv();

	if (listen(srvsockfd, backlog) == -1)
		FATAL("listen");

	ccnt = 0;
	flags = 0;
	memset(&ibuftmpl, 0, sizeof(ibuftmpl));
	if (strlcpy(ibuftmpl.tgtname, tgtname,
	    sizeof(ibuftmpl.tgtname)) >= sizeof(ibuftmpl.tgtname))
		FATALX("target name truncated (%s)", tgtname);
	if (strlcpy(ibuftmpl.sockid, sockid,
	    sizeof(ibuftmpl.sockid)) >= sizeof(ibuftmpl.sockid))
		FATALX("socket id truncated (%s)", sockid);
	ibuftmpl.datamax = datamax;
	ibuftmpl.timeout = timeout;

	if ((kqfd = kqueue()) == -1)
		FATAL("kqueue");

	ctrl_handler = (struct kevcb){ &handle_ctrl, NULL };
	EV_MOD(kqfd, &kev, ctrlfd, EVFILT_READ, EV_ADD, 0, 0, &ctrl_handler);
	srvsock_handler = (struct kevcb){ &handle_srvsock, NULL };
	EV_MOD(kqfd, &kev, srvsockfd, EVFILT_READ, EV_ADD, 0, 0,
	    &srvsock_handler);
	memset(&kev, 0, sizeof(kev));

	if (pledge("proc recvfd sendfd stdio unix", NULL) == -1)
		FATAL("pledge");

	while (kevent(kqfd, NULL, 0, &kev, 1, NULL) != -1)
		KEVENT_HANDLE(&kev);
	FATAL("kevent");
}

void
fork_listener(struct socket *sockcfg, char *tgtname)
{
	extern char	*__progname;

	int	 cfd[2];
	pid_t	 pid;
	char	*argv[12];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC,
	    cfd) == -1)
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

	argv[0] = "listener";
	argv[1] = __progname;
	argv[2] = tgtname;
	argv[3] = sockcfg->id;
	argv[4] = sockcfg->path;
	LLTOS(argv[5], (long long)sockcfg->owner);
	LLTOS(argv[6], (long long)sockcfg->group);
	ITOS(argv[7], sockcfg->mode);
	ITOS(argv[8], sockcfg->backlog < INT_MAX ? sockcfg->backlog : 0);
	LLTOS(argv[9], (long long)sockcfg->datamax);
	LLTOS(argv[10], sockcfg->timeout);
	argv[11] = NULL;

	execvp(__progname, argv);
	FATAL("execvp");
}

static struct keyterm *
check_exclkeyterms(struct keytermq *ktq, char *buf)
{
	struct keyterm	*exclk;

	SIMPLEQ_FOREACH(exclk, ktq, keyterms)
		if (strstr(buf, exclk->str) != NULL)
			return (exclk);

	return (NULL);
}

static struct crange *
check_exclcranges(struct crangeq *crq, struct caddr *addr)
{
	struct crange	*exclr;

	SIMPLEQ_FOREACH(exclr, crq, cranges)
		if (addr_inrange(exclr, addr))
			return (exclr);

	return (NULL);
}

void
proc_data(struct inbuf *ibuf, int kqfd)
{
	struct target	*tgt;
	char		*tgtname, *sockid, *data, *age;
	struct caddr	 addr;
	struct keyterm	*exclk;
	struct crange	*exclr;
	struct client	*clt, *first;
	struct timespec	 now, tsdiff;
	struct table	*tbl;
	size_t		 datalen;
	struct caddrq	 caq;
	struct pfresult	 pfres;
	struct kevent	 kev;

	send(ibuf->datafd, "", 1, MSG_NOSIGNAL);
	close(ibuf->datafd);

	tgtname = ibuf->tgtname;
	sockid = ibuf->sockid;
	data = ibuf->data;
	datalen = ibuf->nr;

	if ((tgt = find_target(&conf->ctargets, tgtname)) == NULL)
		FATALX("invalid target [%s]", tgtname);

	if ((exclk = check_exclkeyterms(&tgt->exclkeyterms, data)) != NULL ||
	    (exclk = check_exclkeyterms(&conf->exclkeyterms, data)) != NULL) {
		data = replace(data, "\n", '\0');
		print_ts_log("Ignored excluded keyterm '%s' :: [%s] <- [%s]",
		    exclk->str, tgtname, data);
		append_data_log(data, datalen);
		return;
	}

	data = replace(data, "\n", '\0');
	memset(&addr, 0, sizeof(addr));
	if (parse_addr(&addr, data) == -1) {
		log_warnx("ignored invalid address (%s)", data);
		return;
	}

	if ((exclr = check_exclcranges(&tgt->exclcranges, &addr)) != NULL ||
	    (exclr = check_exclcranges(&conf->exclcranges, &addr)) != NULL) {
		print_ts_log("Ignored excluded ");
		if (addrvals_cmp(&exclr->first, &exclr->last, exclr->type))
			print_log("network <%s>", exclr->str);
		else
			print_log("address");
		print_log(" :: [%s%s] <- [%s]", tgtname, sockid, data);
		append_data_log(data, datalen);
		return;
	}

	if ((first = clt = TAILQ_FIRST(&cltq)) != NULL) {
		if (timespec_isinfinite(&first->to))
			first = NULL;

		while (clt->tgt != tgt || addrs_cmp(&clt->addr, &addr))
			if ((clt = TAILQ_NEXT(clt, clients)) == NULL)
				break;
	}

	GET_TIME(&now);

	if (clt == NULL) {
		CALLOC(clt, 1, sizeof(*clt));
		if (addrstr(clt->astr, sizeof(clt->astr), &addr) == NULL)
			FATALX("invalid address '%s'", clt->astr);
		clt->addr = addr;
		clt->tgt = tgt;
		DPRINTF("new client (%s, %s) created", clt->astr, tgtname);
	} else {
		DPRINTF("found enqueued client (%s, %s, %d)", clt->astr,
		    tgtname, clt->cnt);
		timespecsub(&now, &clt->ts, &tsdiff);
		if (tsdiff.tv_sec <= 1) {
			print_ts_log("Ignoring [%s]:[%s%s] duplicate hit.\n",
			    clt->astr, tgtname, sockid);
			return;
		}
		clt->exp = 0;
		TAILQ_REMOVE(&cltq, clt, clients);
	}

	SIMPLEQ_INIT(&caq);
	SIMPLEQ_INSERT_TAIL(&caq, &clt->addr, caddrs);

	print_ts_log("Hit :: [%s%s] <- [%s]", tgtname, sockid, data);
	append_data_log(data, datalen);

	clt->cnt++;

	tbl = SIMPLEQ_FIRST(&clt->tgt->cascade);
	while (tbl != NULL && tbl->hits > 0 && clt->cnt > tbl->hits)
		tbl = SIMPLEQ_NEXT(tbl, tables);
	if (tbl == NULL)
		FATALX("open cascade");

	pfexec(&caq, &pfres, "add\n%s%s%s", tbl->name,
	    tbl->flags & FLAG_TABLE_KILL_STATES ? "\nskill" : "",
	    tbl->flags & FLAG_TABLE_KILL_NODES ? "\nnkill" : "");

	print_ts_log("%s [%s]:[%s%s]:(%dx",
	    pfres.nadd > 0 ? ">>> Added" : "Aquired",
	    clt->astr, tgtname, sockid, clt->cnt);

	if (clt->cnt > 1) {
		timespecsub(&now, &clt->ts, &tsdiff);
		age = hrage(&tsdiff);
		print_log(":%s", age);
		free(age);
	}

	print_log(") %s { %s }", pfres.nadd > 0 ? "to" : "from", tbl->name);

	clt->tbl = tbl;
	clt->ts = now;

	if (timespec_isinfinite(&tbl->expire))
		clt->to = TIMESPEC_INFINITE;
	else {
		timespecadd(&now, &tbl->expire, &clt->to);
		age = hrage(&tbl->expire);
		print_log(" for %s", age);
		free(age);
	}

	if (pfres.nkill > 0 || pfres.snkill > 0) {
		print_log(" and killed ");

		if (pfres.nkill > 0)
			print_log("%u state%s", pfres.nkill,
			    pfres.nkill != 1 ? "s" : "");

		if (pfres.snkill > 0)
			print_log("%s%u node%s",
			    pfres.nkill > 0 ? " plus " : "",
			    pfres.snkill, pfres.snkill != 1 ? "s" : "");
	}

	print_log(".\n");

	sort_client_asc(clt);
	if (clt == TAILQ_FIRST(&cltq)) {
		if (first != NULL)
			EV_MOD(kqfd, &kev, (unsigned long)first, EVFILT_TIMER,
			    EV_DELETE, 0, 0, NULL);
		EV_MOD(kqfd, &kev, (unsigned long)clt, EVFILT_TIMER, EV_ADD,
		    0, tbl->expire.tv_sec * 1000, &expire_handler);
	}
}

#define MSG_SEND(fd, fmt, ...)					\
	do {							\
		char	*msg;					\
		if (asprintf(&msg, fmt, ##__VA_ARGS__) == -1)	\
			FATAL("asprintf");			\
		while (send(fd, msg, strlen(msg),		\
		    MSG_NOSIGNAL) == -1) {			\
			if (errno != EAGAIN)			\
				break;				\
			NANONAP;				\
		}						\
		free(msg);					\
	} while (0)

#define TIME_TO_STR(str, tp)						\
	do {								\
		struct timespec	 _tp = *tp;				\
		struct tm	*_tm;					\
		if (_tp.tv_nsec >= 500000000L)				\
			_tp.tv_sec++;					\
		if ((_tm = localtime(&_tp.tv_sec)) == NULL)		\
			FATALX("localtime failed");			\
		if (strftime(str, sizeof(str), TS_FMT, _tm) == 0)	\
			FATALX("strftime overflow");			\
	} while (0)

void
proc_ctrl(struct inbuf *ibuf)
{
	char	*data = ibuf->data, *arg;
	size_t	 datalen = ibuf->nr;
	int	 fd = ibuf->datafd, status;
#if DEBUG
	char	*buf;

	if ((buf = strdup(data)) == NULL)
		FATAL("strdup");
	DPRINTF("received control command: '%s'", replace(buf, "\n", ','));
	free(buf);
#endif

	arg = shift(replace(data, "\n", '\0'), data, datalen);

	if (!strcmp("drop", data))
		status = perform_ctrl_delete(fd, arg, data, datalen,
		    &drop_clients, &drop_clients_r, "dropped");
	else if (!strcmp("dump", data))
		status = perform_ctrl_dump(fd, arg, data, datalen);
	else if (!strcmp("expire", data))
		status = perform_ctrl_delete(fd, arg, data, datalen,
		    &expire_clients, &expire_clients_r, "expired");
	else if (!strcmp("list", data))
		status = perform_ctrl_list(fd, arg, data, datalen);
	else if (!strcmp("reload", data))
		status = perform_ctrl_reload(fd, arg, data, datalen);
	else if (!strcmp("save", data))
		status = perform_ctrl_save(fd, arg, data, datalen);
	else if (!strcmp("self-exclude", data))
		status = perform_ctrl_selfexclude(fd, arg, data, datalen);
	else if (!strcmp("status", data))
		status = perform_ctrl_status(fd, arg, data, datalen);
	else if (!strcmp("verbose", data))
		status = perform_ctrl_verbose(fd, arg, data, datalen);
	else {
		MSG_SEND(fd, "Unknown command.\n");
		status = 0;
	}

	if (errno != EPIPE && status)
		MSG_SEND(fd, "Syntax error.\n");

	close(fd);
}

static int
perform_ctrl_delete(int fd, char *arg, char *data, size_t datalen,
    int (*func)(const char *, struct target *),
    int (*func_r)(const char *, struct target *), const char *action)
{
	int		 cnt, recap;
	struct target	*tgt;
	char		*net;

	if (arg == NULL)
		return (1);

	if (!strcmp("recap", arg)) {
		if ((arg = shift(arg, data, datalen)) == NULL)
			return (1);

		recap = 1;
	} else
		recap = 0;

	net = arg;
	if ((arg = shift(arg, data, datalen)) == NULL)
		tgt = NULL;
	else {
		if ((tgt = find_target(&conf->ctargets, arg)) == NULL) {
			MSG_SEND(fd, "Unknown target.\n");
			return (0);
		}
		if (shift(arg, data, datalen) != NULL)
			return (1);
	}

	cnt = recap ? func_r(net, tgt) : func(net, tgt);

	switch (cnt) {
	case -1:
		MSG_SEND(fd, "Invalid address/network.\n");
		break;
	case 0:
		MSG_SEND(fd, "No client entries found.\n");
		break;
	default:
		MSG_SEND(fd, "%d client entr%s %s.\n", cnt,
		    cnt != 1 ? "ies" : "y", action);
	}

	return (0);
}

static int
perform_ctrl_dump(int fd, char *arg, char *data, size_t datalen)
{
	struct target	*tgt;
	struct client	*clt;

	if (arg == NULL || shift(arg, data, datalen) != NULL)
		return (1);

	if ((tgt = find_target(&conf->ctargets, arg)) == NULL) {
		MSG_SEND(fd, "Unknown target.\n");
		return (0);
	}

	TAILQ_FOREACH(clt, &cltq, clients)
		if (clt->tgt == tgt)
			MSG_SEND(fd, "%s %u %lld\n", clt->astr, clt->cnt,
			    TIMESPEC_SEC_ROUND(&clt->ts));

	return (0);
}

static int
perform_ctrl_list(int fd, char *arg, char *data, size_t datalen)
{
	int		 act, cnt;
	struct target	*tgt = NULL;
	struct crange	*r = NULL;
	struct timespec	 now, tsdiff;
	struct client	*clt;
	char		*age, tstr[TS_SIZE];

	if (arg != NULL && !strcmp("active", arg)) {
		act = 1;
		arg = shift(arg, data, datalen);
	} else
		act = 0;

	if (arg != NULL) {
		if ((r = parse_crange(arg)) != NULL)
			arg = shift(arg, data, datalen);
		if (arg != NULL) {
			if ((tgt = find_target(&conf->ctargets,
			    arg)) == NULL) {
				MSG_SEND(fd, "Unknown target");
				if (r == NULL)
					MSG_SEND(fd, " or invalid "
					    "address/network");
				MSG_SEND(fd, ".\n");
				return (0);
			}
			if (shift(arg, data, datalen) != NULL)
				return (1);
		}
	}

	cnt = 0;
	GET_TIME(&now);

	TAILQ_FOREACH_REVERSE(clt, &cltq, clientq, clients) {
		if ((act && clt->exp) ||
		    (r != NULL && !addr_inrange(r, &clt->addr)) ||
		    (tgt != NULL && clt->tgt != tgt))
			continue;

		timespecsub(&now, &clt->ts, &tsdiff);
		age = hrage(&tsdiff);
		MSG_SEND(fd, "[%s]:[%s]:(%dx:%s)\n\t", clt->astr,
		    clt->tgt->name, clt->cnt, age);
		free(age);

		if (timespec_isinfinite(&clt->to)) {
			if (clt->exp)
				MSG_SEND(fd, "never gets dropped\n");
			else
				MSG_SEND(fd, "in { %s }, never expires\n",
				    clt->tbl->name);
		} else {
			timespecsub(&clt->to, &now, &tsdiff);
			age = hrage(&tsdiff);
			TIME_TO_STR(tstr, &clt->to);
			if (clt->exp)
				MSG_SEND(fd, "getting dropped in %s,\n\ton "
				    "[%s]\n", age, tstr);
			else
				MSG_SEND(fd, "more %s in { %s },\n\tuntil "
				    "[%s]\n", age, clt->tbl->name, tstr);
			free(age);
		}
		cnt++;
	}

	if (cnt == 0)
		MSG_SEND(fd, "No client entries found.\n");
	else
		MSG_SEND(fd, "%d client entr%s found.\n", cnt,
		    cnt != 1 ? "ies" : "y");

	return (0);
}

static int
perform_ctrl_reload(int fd, char *arg, char *data, size_t datalen)
{
	extern int	 privfd;

	enum msgtype	 mt;

	if (shift(arg, data, datalen) != NULL)
		return (1);

	mt = CONF_RELOAD;
	WRITE(privfd, &mt, sizeof(mt));
	/* wait for reply */
	READ(privfd, &mt, sizeof(mt));
	MSG_SEND(fd, mt == ACK ? "Done.\n" : "Failed.\n");

	return (0);
}

static int
perform_ctrl_save(int fd, char *arg, char *data, size_t datalen)
{
	int		 cnt;
	struct target	*tgt;

	if (arg == NULL || shift(arg, data, datalen) != NULL)
		return (1);

	if ((tgt = find_target(&conf->ctargets, arg)) == NULL) {
		MSG_SEND(fd, "Unknown target.\n");
		return (0);
	}

	if (*tgt->persist == '\0') {
		MSG_SEND(fd, "No persist file specified.\n");
		return (0);
	}

	if ((cnt = save(tgt)) != -1)
		MSG_SEND(fd, "%d client entr%s written.\n", cnt,
		    cnt != 1 ? "ies" : "y");
	else
		MSG_SEND(fd, "Failed. Check the system log.\n");

	return (0);
}

static int
perform_ctrl_selfexclude(int fd, char *arg, char *data, size_t datalen)
{
	struct crange	*r, *r2;

	if (shift(arg, data, datalen) != NULL)
		return (1);

	r = SIMPLEQ_FIRST(&conf->exclcranges);
	if (arg == NULL) {
		if (*r->str != '\0')
			MSG_SEND(fd, "[%s]\n", r->str);
		else
			MSG_SEND(fd, "None.\n");
		return (0);
	}
	if (!strcmp("remove", arg)) {
		memset(r, 0, sizeof(*r));
		print_ts_log("Removed self exclude.\n");
		MSG_SEND(fd, "Done.\n");
		return (0);
	}
	if ((r2 = parse_crange(arg)) == NULL) {
		MSG_SEND(fd, "Invalid address/network.\n");
		return (0);
	}
	if (cranges_eq(r, r2)) {
		free(r2);
		MSG_SEND(fd, "Ditto.\n");
		return (0);
	}
	SIMPLEQ_REMOVE_HEAD(&conf->exclcranges, cranges);
	free(r);
	SIMPLEQ_INSERT_HEAD(&conf->exclcranges, r2, cranges);
	print_ts_log("Updated self exclude to [%s].\n", r2->str);
	MSG_SEND(fd, "Done.\n");

	return (0);
}

static int
perform_ctrl_status(int fd, char *arg, char *data, size_t datalen)
{
	struct crange	*r;
	int		*cnt, c;
	struct client	*clt;
	struct target	*tgt;
	char		*age, tstr[TS_SIZE];
	struct timespec	 now, tsdiff;

	if (arg != NULL)
		return (1);

	r = SIMPLEQ_FIRST(&conf->exclcranges);
	MSG_SEND(fd, "Self-exclude: [%s]\nVerbosity level: %d\n",
	    *r->str != '\0' ? r->str : "N/A", log_getverbose());
	c = 0;
	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		c++;
	CALLOC(cnt, c, sizeof(int));
	TAILQ_FOREACH(clt, &cltq, clients) {
		c = 0;
		SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
			if (clt->tgt == tgt) {
				cnt[c]++;
				break;
			} else
				c++;
	}
	c = 0;
	MSG_SEND(fd, "Client count:\n");
	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		MSG_SEND(fd, "\ttarget [%s]: %d\n", tgt->name, cnt[c++]);
	free(cnt);
	clt = TAILQ_FIRST(&cltq);
	if (clt == NULL || timespec_isinfinite(&clt->to)) {
		MSG_SEND(fd, "No event pending.\n");
		return (0);
	}
	TIME_TO_STR(tstr, &clt->to);
	GET_TIME(&now);
	timespecsub(&now, &clt->ts, &tsdiff);
	age = hrage(&tsdiff);
	MSG_SEND(fd, "Next scheduled event:\n\t[%s]:[%s]:(%dx:%s)\n\t\t",
	    clt->astr, clt->tgt->name, clt->cnt, age);
	free(age);
	if (clt->exp)
		MSG_SEND(fd, "getting dropped");
	else
		MSG_SEND(fd, "expires from { %s }", clt->tbl->name);
	timespecsub(&clt->to, &now, &tsdiff);
	age = hrage(&tsdiff);
	MSG_SEND(fd, " in %s,\n\t\ton [%s]\n", age, tstr);
	free(age);

	return (0);
}

static int
perform_ctrl_verbose(int fd, char *arg, char *data, size_t datalen)
{
	extern int	 privfd;

	int		 v;
	const char	*err;
	enum msgtype	 mt;

	if (shift(arg, data, datalen) != NULL)
		return (1);

	if (arg == NULL) {
		MSG_SEND(fd, "%d\n", log_getverbose());
		return (0);
	}
	v = strtonum(arg, 0, INT_MAX, &err);
	if (err != NULL) {
		MSG_SEND(fd, "Verbosity level %s.\n", err);
		return (0);
	}
	log_setverbose(v);
	ITOE(ENV_VERBOSE, v);

	mt = SET_VERBOSE;
	WRITE2(privfd, &mt, sizeof(mt), &v, sizeof(v));
	/* wait for reply */
	READ(privfd, &mt, sizeof(mt));
	MSG_SEND(fd, mt == ACK ? "Done.\n" : "Failed.\n");

	return (0);
}
