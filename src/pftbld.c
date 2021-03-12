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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "pftbld.h"

static __dead void
		 usage(void);
static void	 handle_signal(struct kevent *);
static void	 handle_privreq(struct kevent *);
static void	 exec_pfcmd(int);
static void	 handle_persist(int);
static void	 set_verbose(int);
static void	 conf_reload(int);
static void	 send_verbose(int);
static __dead void
		 shutdown_main(void);
static void	 send_conf(int);

extern struct config	*conf;

char	*basepath = NULL;
char	 conffile[PATH_MAX] = CONF_FILE;
int	 privfd;

const struct procfunc	 process[] = {
	[PROC_PFTBLD] = { "pftbld", pftbld },
	[PROC_LOGGER] = { "logger", logger },
	[PROC_SCHEDULER] = { "scheduler", scheduler },
	[PROC_LISTENER] = { "listener", listener },
	[PROC_TINYPFCTL] = { "tinypfctl", tinypfctl }
};

static __dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage:\t%s [-dnuv] [-b <path>] [-f <path>] "
	    "[-s <socket>]\n\t%s [-v] -p <socket>\n", __progname, __progname);
	exit(1);
}

static void
handle_signal(struct kevent *kev)
{
	extern int	 sched_cfd;
	extern pid_t	 sched_pid, logger_pid;

	int	 sig = kev->ident;

	switch (sig) {
	case SIGHUP:
		log_debug("reload started");
		if (reload_conf() == 0) {
			send_conf(sched_cfd);
			log_info("reload completed successfully");
		} else
			log_info("reload aborted with errors");
		break;
	case SIGINT:
	case SIGTERM:
		kill(sched_pid, SIGTERM);
		break;
	case SIGUSR1:
		if (logger_pid) {
			fork_logger();
			log_info("restarted logger %s", conf->log);
		} else
			log_debug("no logger running");
		break;
	default:
		FATALX("unexpected signal (%d)", sig);
	}
}

static void
handle_privreq(struct kevent *kev)
{
	int		 pfd;
	enum msgtype	 mt;

	if (kev->flags & EV_EOF)
		FATALX("connection closed unexpectedly");

	pfd = kev->ident;
	RECV(pfd, &mt, sizeof(mt));
	switch (mt) {
	case MSG_EXEC_PFCMD:
		exec_pfcmd(pfd);
		break;
	case MSG_HANDLE_PERSIST:
		handle_persist(pfd);
		break;
	case MSG_SET_VERBOSE:
		set_verbose(pfd);
		break;
	case MSG_CONF_RELOAD:
		conf_reload(pfd);
		break;
	case MSG_SHUTDOWN_MAIN:
		shutdown_main();
		/* NOTREACHED */
	default:
		FATALX("invalid message type (%d)", mt);
	}
}

void
pfexec(struct pfresult *pfres, struct pfcmd *cmd)
{
	enum msgtype	 mt;
	int		 tfd;
	size_t		 iovcnt, i;
	unsigned long	 cmdacnt;
	struct msghdr	 msg;
	struct iovec	*iov;
	struct caddr	*ca;
	ssize_t		 ns;

	mt = MSG_EXEC_PFCMD;
	ISEND(privfd, 2, &mt, sizeof(mt), cmd, sizeof(*cmd));
	while ((tfd = recv_fd(&mt, sizeof(mt), privfd)) == -1)
		NANONAP;
	if (mt != MSG_ACK)
		FATALX("invalid message type (%d)", mt);

	cmdacnt = cmd->addrcnt;

	memset(&msg, 0, sizeof(msg));
	iovcnt = IOV_CNT(cmdacnt);
	if ((iov = reallocarray(NULL, iovcnt, sizeof(*iov))) == NULL)
		FATAL("reallocarray");
	for (i = 0; i < iovcnt; i++)
		iov[i].iov_len = sizeof(struct pfr_addr);
	msg.msg_iov = iov;

	for (;;) {
		for (i = 0; i < iovcnt; i++) {
			if ((ca = SIMPLEQ_FIRST(&cmd->addrq)) == NULL)
				FATALX("wrong address count");
			SIMPLEQ_REMOVE_HEAD(&cmd->addrq, caddrs);
			iov[i].iov_base = &ca->pfaddr;
		}
		msg.msg_iovlen = iovcnt;
		if ((ns = sendmsg(tfd, &msg, 0)) == -1)
			FATAL("sendmsg");
		if (iovcnt * sizeof(struct pfr_addr) - ns != 0)
			FATALX("sendmsg buffer too small");
		if ((cmdacnt -= iovcnt) == 0)
			break;
		iovcnt = IOV_CNT(cmdacnt);
	}

	free(iov);
	/* wait for reply */
	RECV(tfd, pfres, sizeof(*pfres));
	close(tfd);
	DPRINTF("received pfresult(nadd:%lu, ndel:%lu, nkill:%lu, snkill:%lu)",
	    pfres->nadd, pfres->ndel, pfres->nkill, pfres->snkill);
}

__dead void
pftbld(int argc, char *argv[])
{
	extern char	*__progname;
	extern int	 logfd, sched_cfd;
	extern pid_t	 sched_pid, logger_pid;

	struct kevent	 kev;
	int		 kqfd, c, pfd[2];
	int		 debug = 0, verbose = 0, noaction = 0, unload = 0;
	char		*sockfile = SOCK_FILE;
	struct statfd	*sfd;
	struct target	*tgt;
	struct socket	*sock;
	struct kevcb	 signal_handler, privreq_handler;

	while ((c = getopt(argc, argv, "b:df:np:s:uv")) != -1) {
		switch (c) {
		case 'b':
			if (*(basepath = optarg) != '/')
				errx(1, "base path must be absolute");
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			CANONICAL_PATH_SET(conffile, optarg,
			    "configuration file", warnx, exit(1));
			break;
		case 'n':
			noaction = 1;
			break;
		case 'p':
			optreset = optind = 1;
			while ((c = getopt(argc, argv, "p:v")) != -1) {
				switch (c) {
				case 'v':
					verbose = 1;
					break;
				case 'p':
					sockfile = optarg;
					break;
				default:
					usage();
				}
			}
			sockpipe(sockfile, verbose);
			/* NOTREACHED */
		case 's':
			sockfile = optarg;
			break;
		case 'u':
			unload = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	log_init(__progname, debug ? debug : 1, verbose);

	argc -= optind;
	if (argc > 0)
		usage();

	if (geteuid())
		errx(1, "need root privileges");

	if (getpwnam(PFTBLD_USER) == NULL)
		errx(1, "missing user %s", PFTBLD_USER);

	CALLOC(conf, 1, sizeof(*conf));

	if ((c = parse_conf()) > 0)
		errx(1, "%d configuration error%s found", c,
		    c != 1 ? "s" : "");

	if (noaction) {
		if (verbose) {
			sfd = create_statfd(STDERR_FILENO);
			print_conf(sfd);
			free(sfd);
		} else
			fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	if (unload)
		conf->flags |= FLAG_GLOBAL_UNLOAD;

	sock = &conf->ctrlsock;
	CANONICAL_PATH_SET(sock->path, sockfile, "control socket", warnx,
	    exit(1));
	if (prefill_socketopts(sock) == -1)
		FATAL("prefill control socket options");

	if (!debug && daemon(1, 0) == -1)
		FATAL("daemon");

	log_procinit("main");

	log_init(__progname, debug, verbose);

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pfd) == -1)
		FATAL("socketpair");

	privfd = pfd[1];

	ITOE(ENV_DEBUG, debug);
	ITOE(ENV_VERBOSE, verbose);
	ITOE(ENV_LOGFD, logfd);

	if (conf->flags & FLAG_GLOBAL_NOLOG)
		log_info("logging is disabled");
	else
		fork_logger();

	print_ts_log("Hello.\n");

	fork_scheduler();

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets)
			fork_listener(sock, tgt->name);

	fork_listener(&conf->ctrlsock, "");

	send_conf(sched_cfd);

	if ((kqfd = kqueue()) == -1)
		FATAL("kqueue");

	signal_handler = (struct kevcb){ &handle_signal, NULL };
	EV_MOD(kqfd, &kev, SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0,
	    &signal_handler);
	EV_MOD(kqfd, &kev, SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0,
	    &signal_handler);
	EV_MOD(kqfd, &kev, SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0,
	    &signal_handler);
	EV_MOD(kqfd, &kev, SIGUSR1, EVFILT_SIGNAL, EV_ADD, 0, 0,
	    &signal_handler);
	privreq_handler = (struct kevcb){ &handle_privreq, NULL };
	EV_MOD(kqfd, &kev, pfd[0], EVFILT_READ, EV_ADD, 0, 0,
	    &privreq_handler);
	memset(&kev, 0, sizeof(kev));

	if (pledge("chown cpath exec fattr getpw proc recvfd rpath sendfd "
	    "unix stdio wpath", NULL) == -1)
		FATAL("pledge");

	while (kevent(kqfd, NULL, 0, &kev, 1, NULL) != -1)
		KEVENT_HANDLE(&kev);
	FATAL("kevent");
}

static void
exec_pfcmd(int pfd)
{
	struct pfcmd	 cmd;
	int		 tfd;
	enum msgtype	 mt;

	RECV(pfd, &cmd, sizeof(cmd));
	tfd = fork_tinypfctl(&cmd);
	mt = MSG_ACK;
	while (send_fd(tfd, &mt, sizeof(mt), pfd) == -1)
		NANONAP;
	close(tfd);
}

static void
handle_persist(int pfd)
{
	char		 path[sizeof(((struct target *)0)->persist)];
	char		*dpath, *dir;
	struct stat	 sb;
	int		 fd;
	enum msgtype	 mt;

#define MODE_FILE_WRONLY	0200
#define MODE_FILE_RDWR		0666

	RECV(pfd, path, sizeof(path));
	STRDUP(dpath, path);
	if ((dir = dirname(dpath)) == NULL) {
		log_warn("persist directory");
		free(dpath);
		goto fail;
	}
	if (stat(dir, &sb) == -1) {
		log_warn("get permissions of persist directory %s", dir);
		free(dpath);
		goto fail;
	}
	free(dpath);

	if (unlink(path) == -1 && errno != ENOENT) {
		log_warn("unlink persist file %s", path);
		goto fail;
	}
	if ((fd = open(path, O_CREAT | O_EXCL | O_SYNC | O_WRONLY,
	    MODE_FILE_WRONLY)) == -1) {
		log_warn("open persist file %s", path);
		goto fail;
	}
	mt = MSG_ACK;
	SEND(pfd, &mt, sizeof(mt));
	while (send_fd(fd, &mt, sizeof(mt), pfd) == -1)
		NANONAP;
	/* wait for reply */
	RECV(pfd, &mt, sizeof(mt));
	if (mt == MSG_ACK &&
	    (fchown(fd, sb.st_uid, sb.st_gid) == -1 ||
	    fchmod(fd, MODE_FILE_RDWR & sb.st_mode) == -1))
		log_warn("set permissions on persist file %s", path);
	close(fd);
	return;

fail:
	mt = MSG_NAK;
	SEND(pfd, &mt, sizeof(mt));
}

static void
set_verbose(int pfd)
{
	extern pid_t	 logger_pid;
	extern int	 logger_cfd;

	int		 v;
	enum msgtype	 mt;
	struct target	*tgt;
	struct socket	*sock;

	RECV(pfd, &v, sizeof(v));
	log_setverbose(v);
	ITOE(ENV_VERBOSE, v);
	if (logger_pid)
		send_verbose(logger_cfd);
	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets)
			send_verbose(sock->ctrlfd);
	mt = MSG_ACK;
	SEND(pfd, &mt, sizeof(mt));
}

static void
send_verbose(int ctrlfd)
{
	enum msgtype	 mt = MSG_SET_VERBOSE;
	int		 v = log_getverbose();

	ISEND(ctrlfd, 2, &mt, sizeof(mt), &v, sizeof(v));
	/* wait for reply */
	RECV(ctrlfd, &mt, sizeof(mt));
	if (mt != MSG_ACK)
		FATALX("verbose level update failed (%d)", mt);
}

static void
conf_reload(int pfd)
{
	enum msgtype	 mt = MSG_ACK;

	SEND(pfd, &mt, sizeof(mt));

	if (raise(SIGHUP) == -1)
		FATAL("raise");
}

static __dead void
shutdown_main(void)
{
	extern pid_t	 logger_pid;

	struct socket	*sock;
	struct target	*tgt;

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets)
			if (sock->pid)
				kill(sock->pid, SIGUSR2);

	sock = &conf->ctrlsock;
	if (!sock->pid)
		goto end;

	kill(sock->pid, SIGUSR2);
	if (unlink(sock->path) == -1)
		log_warn("failed deleting control socket %s", sock->path);

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets) {
			if (unlink(sock->path) != -1)
				continue;
			log_warn("failed deleting data socket %s", sock->path);
		}

end:
	print_ts_log("Good Bye.\n");

	if (logger_pid) {
		NANONAP;
		kill(logger_pid, SIGUSR2);
	}

	exit(0);
}

static void
send_conf(int fd)
{
	enum msgtype	 mt = MSG_UPDATE_CONFIG;
	enum msgtype	 inext = MSG_QUEUE_NEXTITEM;
	enum msgtype	 iend = MSG_QUEUE_ENDITEMS;
	size_t		 n;
	struct socket	*sock;
	struct target	*tgt;
	struct crange	*cr;
	struct ptr	*kt;
	struct table	*tab;

	SEND(fd, &mt, sizeof(mt));
	while (send_fd(conf->ctrlsock.ctrlfd, conf, sizeof(*conf), fd) == -1)
		NANONAP;

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		ISEND(fd, 2, &inext, sizeof(inext), tgt, sizeof(*tgt));

		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets) {
			SEND(fd, &inext, sizeof(inext));
			while (send_fd(sock->ctrlfd, sock, sizeof(*sock),
			    fd) == -1)
				NANONAP;
		}
		SEND(fd, &iend, sizeof(iend));

		SIMPLEQ_FOREACH(cr, &tgt->exclcranges, cranges)
			ISEND(fd, 2, &inext, sizeof(inext), cr, sizeof(*cr));
		SEND(fd, &iend, sizeof(iend));

		SIMPLEQ_FOREACH(kt, &tgt->exclkeyterms, ptrs) {
			n = strlen(kt->p) + 1;
			ISEND(fd, 4, &inext, sizeof(inext), kt, sizeof(*kt),
			    &n, sizeof(n), kt->p, n);
		}
		SEND(fd, &iend, sizeof(iend));

		SIMPLEQ_FOREACH(tab, &tgt->cascade, tables)
			ISEND(fd, 2, &inext, sizeof(inext), tab, sizeof(*tab));
		SEND(fd, &iend, sizeof(iend));
	}
	SEND(fd, &iend, sizeof(iend));

	SIMPLEQ_FOREACH(cr, &conf->exclcranges, cranges)
		ISEND(fd, 2, &inext, sizeof(inext), cr, sizeof(*cr));
	SEND(fd, &iend, sizeof(iend));

	SIMPLEQ_FOREACH(kt, &conf->exclkeyterms, ptrs) {
		n = strlen(kt->p) + 1;
		ISEND(fd, 4, &inext, sizeof(inext), kt, sizeof(*kt), &n,
		    sizeof(n), kt->p, n);
	}
	SEND(fd, &iend, sizeof(iend));

	RECV(fd, &mt, sizeof(mt));
	if (mt != MSG_ACK)
		FATALX("config update failed (%d)", mt);
}

int
main(int argc, char *argv[])
{
	extern char	*__progname;

	int	 i = NUM_PROCS;

	while (--i >= 0)
		if (!strcmp(process[i].name, __progname)) {
			process[i].call(argc, argv);
			/* NOTREACHED */
		}
	FATALX("invalid process '%s'", __progname);
}
