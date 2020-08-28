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

#include <net/if.h>

#include <sys/stat.h>

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

char	*conffile = CONF_FILE;
int	 privfd;

static __dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage:\t%s [-dnuv] [-f <path>] [-s <socket>]\n"
	    "\t%s [-v] -p <socket>\n", __progname, __progname);
	exit(1);
}

static void
handle_signal(struct kevent *kev)
{
	extern int	 sched_cfd;
	extern pid_t	 sched_pid, logger_pid;

	int sig = kev->ident;

	switch (sig) {
	case SIGHUP:
		log_debug("reload started");
		if (reload_conf() == 0) {
			send_conf(sched_cfd);
			log_info("reload completed successfully");
		} else
			log_info("reload aborted with errors");
		break;
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
	READ(pfd, &mt, sizeof(mt));
	switch (mt) {
	case EXEC_PFCMD:
		exec_pfcmd(pfd);
		break;
	case HANDLE_PERSIST:
		handle_persist(pfd);
		break;
	case SET_VERBOSE:
		set_verbose(pfd);
		break;
	case CONF_RELOAD:
		conf_reload(pfd);
		break;
	case SHUTDOWN_MAIN:
		shutdown_main();
		/* NOTREACHED */
	default:
		FATALX("invalid message type (%d)", mt);
	}
}

void
pfexec(struct caddrq *caq, struct pfresult *pfres, const char *fmt, ...)
{
	va_list		 ap;
	enum msgtype	 mt;
	char		*cmd;
	int		 clen;
	struct caddr	*ca;

	va_start(ap, fmt);
	if ((clen = vasprintf(&cmd, fmt, ap)) == -1)
		FATAL("vasprintf");
	va_end(ap);

	mt = EXEC_PFCMD;
	if (write(privfd, &mt, sizeof(mt)) == -1 ||
	    write(privfd, &clen, sizeof(clen)) == -1 ||
	    write(privfd, cmd, clen) == -1)
		FATAL("write");
	free(cmd);
	mt = QUEUE_NEXTITEM;
	while ((ca = SIMPLEQ_FIRST(caq)) != NULL) {
		WRITE2(privfd, &mt, sizeof(mt), ca, sizeof(*ca));
		SIMPLEQ_REMOVE_HEAD(caq, caddrs);
	}
	mt = QUEUE_ENDITEMS;
	WRITE(privfd, &mt, sizeof(mt));
	/* wait for reply */
	READ(privfd, pfres, sizeof(*pfres));
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
	struct crange	*self;
	struct target	*tgt;
	struct socket	*sock;
	struct kevcb	 signal_handler, privreq_handler;

	while ((c = getopt(argc, argv, "df:np:s:uv")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
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
		fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	if (unload)
		conf->flags |= FLAG_GLOBAL_UNLOAD;

	sock = &conf->ctrlsock;
	if (strlcpy(sock->path, sockfile,
	    sizeof(sock->path)) >= sizeof(sock->path))
		FATALX("control socket path '%s' too long", sockfile);
	if (prefill_socketopts(sock) == -1)
		FATAL("prefill control socket options");

	CALLOC(self, 1, sizeof(*self));
	SIMPLEQ_INSERT_HEAD(&conf->exclcranges, self, cranges);

	if (!debug && daemon(1, 0) == -1)
		FATAL("daemon");

	log_procinit("main");

	log_init(__progname, debug, verbose);

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC,
	    pfd) == -1)
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
	struct pfresult	 pfres;
	char		*cmd;
	int		 clen;
	struct caddrq	 caq;
	enum msgtype	 mt;
	struct caddr	*ca;
	size_t		 acnt;

	READ(pfd, &clen, sizeof(clen));
	MALLOC(cmd, clen + 1);
	READ(pfd, cmd, clen);
	cmd[clen] = '\0';
	SIMPLEQ_INIT(&caq);
	acnt = 0;
	while (1) {
		READ(pfd, &mt, sizeof(mt));
		if (mt == QUEUE_ENDITEMS)
			break;
		if (mt != QUEUE_NEXTITEM)
			FATALX("invalid message type (%d)", mt);
		MALLOC(ca, sizeof(*ca));
		READ(pfd, ca, sizeof(*ca));
		SIMPLEQ_INSERT_TAIL(&caq, ca, caddrs);
		acnt++;
	}
	fork_tinypfctl(&pfres, cmd, &caq, acnt);
	/* wait for reply */
	free(cmd);
	WRITE(pfd, &pfres, sizeof(pfres));
}

static void
handle_persist(int pfd)
{
	size_t		 len;
	char		*path, cpath[PATH_MAX], *file, *dpath, *dir;
	enum pathres	 pres;
	struct stat	 dstat;
	int		 fd;
	enum msgtype	 mt;

#define MODE_FILE_WRONLY	0200
#define MODE_FILE_RDWR		0666

	READ(pfd, &len, sizeof(len));
	MALLOC(path, len);
	READ(pfd, path, len);
	pres = check_path(path, cpath, sizeof(cpath), &file);
	switch (pres) {
	case PATH_OK:
		break;
	case PATH_EMPTY:
		log_warnx("persist path is empty");
		free(path);
		goto fail;
	case PATH_RELATIVE:
		log_warnx("persist path '%s' is relative", path);
		free(path);
		goto fail;
	case PATH_INVALID:
		log_warnx("invalid persist path '%s'", path);
		free(path);
		goto fail;
	case PATH_DIRECTORY:
		log_warnx("persist path %s is a directory", cpath);
		free(path);
		goto fail;
	case PATH_FILENAME:
		if (errno)
			log_warn("persist file name");
		else
			log_warnx("invalid persist file '%s'", file);
		free(path);
		goto fail;
	default:
		FATALX("invalid path check result (%d)", pres);
	}
	free(path);
	if ((dpath = strdup(cpath)) == NULL)
		FATAL("strdup");
	if ((dir = dirname(dpath)) == NULL) {
		log_warn("persist directory");
		free(dpath);
		goto fail;
	}
	free(dpath);
	if (stat(dir, &dstat) == -1) {
		log_warn("persist directory %s permission error", dir);
		goto fail;
	}

	if (unlink(cpath) == -1 && errno != ENOENT) {
		log_warn("persist file %s access error", cpath);
		goto fail;
	}
	if ((fd = open(cpath, O_CREAT | O_EXCL | O_SYNC | O_WRONLY,
	    MODE_FILE_WRONLY)) == -1)
		FATAL("open");

	mt = ACK;
	WRITE(pfd, &mt, sizeof(mt));
	while (send_fd(fd, &mt, sizeof(mt), pfd) == -1)
		NANONAP;
	/* wait for reply */
	READ(pfd, &mt, sizeof(mt));
	if (mt == ACK &&
	    (fchown(fd, dstat.st_uid, dstat.st_gid) == -1 ||
	    fchmod(fd, MODE_FILE_RDWR & dstat.st_mode) == -1))
		log_warn("failed setting permissions on persist file %s",
		    cpath);
	close(fd);
	return;

fail:
	mt = NAK;
	WRITE(pfd, &mt, sizeof(mt));
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

	READ(pfd, &v, sizeof(v));
	log_setverbose(v);
	ITOE(ENV_VERBOSE, v);
	if (logger_pid)
		send_verbose(logger_cfd);
	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets)
		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets)
			send_verbose(sock->ctrlfd);
	mt = ACK;
	WRITE(pfd, &mt, sizeof(mt));
}

static void
send_verbose(int ctrlfd)
{
	enum msgtype	 mt = SET_VERBOSE;
	int		 v = log_getverbose();

	WRITE2(ctrlfd, &mt, sizeof(mt), &v, sizeof(v));
	/* wait for reply */
	READ(ctrlfd, &mt, sizeof(mt));
	if (mt != ACK)
		FATALX("verbose level update failed (%d)", mt);
}

static void
conf_reload(int pfd)
{
	enum msgtype	 mt = ACK;

	WRITE(pfd, &mt, sizeof(mt));

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
				kill(sock->pid, SIGINT);

	sock = &conf->ctrlsock;
	if (!sock->pid)
		goto end;

	kill(sock->pid, SIGINT);
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
		kill(logger_pid, SIGINT);
	}

	exit(0);
}

static void
send_conf(int fd)
{
	enum msgtype	 mt = UPDATE_CONFIG;
	enum msgtype	 inext = QUEUE_NEXTITEM;
	enum msgtype	 iend = QUEUE_ENDITEMS;
	size_t		 n;
	struct socket	*sock;
	struct target	*tgt;
	struct crange	*cr;
	struct keyterm	*kt;
	struct table	*tab;

	WRITE(fd, &mt, sizeof(mt));
	while (send_fd(conf->ctrlsock.ctrlfd, conf, sizeof(*conf), fd) == -1)
		NANONAP;

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		WRITE2(fd, &inext, sizeof(inext), tgt, sizeof(*tgt));

		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets) {
			WRITE(fd, &inext, sizeof(inext));
			while (send_fd(sock->ctrlfd, sock, sizeof(*sock),
			    fd) == -1)
				NANONAP;
		}
		WRITE(fd, &iend, sizeof(iend));

		SIMPLEQ_FOREACH(cr, &tgt->exclcranges, cranges)
			WRITE2(fd, &inext, sizeof(inext), cr, sizeof(*cr));
		WRITE(fd, &iend, sizeof(iend));

		SIMPLEQ_FOREACH(kt, &tgt->exclkeyterms, keyterms) {
			WRITE2(fd, &inext, sizeof(inext), kt, sizeof(*kt));
			n = strlen(kt->str) + 1;
			WRITE2(fd, &n, sizeof(n), kt->str, n);
		}
		WRITE(fd, &iend, sizeof(iend));

		SIMPLEQ_FOREACH(tab, &tgt->cascade, tables)
			WRITE2(fd, &inext, sizeof(inext), tab, sizeof(*tab));
		WRITE(fd, &iend, sizeof(iend));
	}
	WRITE(fd, &iend, sizeof(iend));

	SIMPLEQ_FOREACH(cr, &conf->exclcranges, cranges)
		WRITE2(fd, &inext, sizeof(inext), cr, sizeof(*cr));
	WRITE(fd, &iend, sizeof(iend));

	SIMPLEQ_FOREACH(kt, &conf->exclkeyterms, keyterms) {
		WRITE2(fd, &inext, sizeof(inext), kt, sizeof(*kt));
		n = strlen(kt->str) + 1;
		WRITE2(fd, &n, sizeof(n), kt->str, n);
	}
	WRITE(fd, &iend, sizeof(iend));

	READ(fd, &mt, sizeof(mt));
	if (mt != ACK)
		FATALX("config update failed (%d)", mt);
}

int
main(int argc, char *argv[])
{
	extern char	*__progname;

	if (!strcmp("listener", __progname))
		listener(argc, argv);

	if (!strcmp("logger", __progname))
		logger(argc, argv);

	if (!strcmp("pftbld", __progname))
		pftbld(argc, argv);

	if (!strcmp("scheduler", __progname))
		scheduler(argc, argv);

	if (!strcmp("tinypfctl", __progname))
		tinypfctl(argc, argv);

	FATALX("invalid process '%s'", __progname);
}
