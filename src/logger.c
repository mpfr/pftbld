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
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#include "log.h"
#include "pftbld.h"

static void	 handle_signal(struct kevent *);
static void	 handle_ctrl(struct kevent *);
static void	 handle_pipe(struct kevent *);
static void	 term_logger(void);
static void	 dispatch_logger(void);
static void	 send_logfd(pid_t);
static void	 plog_va(char *, va_list);

extern struct config	*conf;

int	 logger_cfd, pipefd, logfd = -1;
pid_t	 logger_pid = 0;

static void
handle_signal(struct kevent *kev)
{
	int	 sig = kev->ident;

	switch (sig) {
	case SIGUSR2:
		if (fsync(logfd) == -1)
			log_warn("log flush failed");
		exit(0);
	default:
		FATALX("unexpected signal (%d)", sig);
	}
}

static void
handle_ctrl(struct kevent *kev)
{
	enum msgtype	 mt;
	int		 v;

	if (kev->flags & EV_EOF)
		FATALX("connection closed unexpectedly");

	RECV(logger_cfd, &mt, sizeof(mt));
	switch (mt) {
	case MSG_SET_VERBOSE:
		RECV(logger_cfd, &v, sizeof(v));
		log_setverbose(v);
		break;
	default:
		FATALX("invalid ipc message type (%d)", mt);
	}
	mt = MSG_ACK;
	SEND(logger_cfd, &mt, sizeof(mt));
}

static void
handle_pipe(struct kevent *kev)
{
	char	*buf;
	ssize_t	 nr, nw, n, nx;

	if (kev->flags & EV_EOF)
		FATALX("connection closed unexpectedly");

	n = kev->data;
	MALLOC(buf, n);
	nr = nw = 0;
	do {
		if ((nx = read(pipefd, &buf[nr], n - nr)) == -1)
			FATAL("read");
		nr += nx;
		if ((nx = write(logfd, &buf[nw], nr - nw)) == -1)
			FATAL("write");
		nw += nx;
	} while (nr < n || nw < nr);
	free(buf);
}

__dead void
logger(int argc, char *argv[])
{

#define MODE_LOGFILE	0640

	int		 debug, verbose, kqfd;
	struct kevent	 kev;
	struct kevcb	 signal_handler, ctrl_handler, pipe_handler;

	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);

	ETOI(debug, ENV_DEBUG);
	ETOI(verbose, ENV_VERBOSE);
	log_init(argv[1], debug, verbose);
	setproctitle("%s", __func__);

	ETOI(logger_cfd, ENV_CTRLFD);
	ETOI(pipefd, ENV_LOGFD);

	if ((logfd = open(argv[2], O_WRONLY | O_CREAT | O_APPEND,
	    MODE_LOGFILE)) == -1)
		FATAL("open");

	drop_priv();

	if ((kqfd = kqueue()) == -1)
		FATAL("kqueue");

	signal_handler = (struct kevcb){ &handle_signal, NULL };
	EV_MOD(kqfd, &kev, SIGUSR2, EVFILT_SIGNAL, EV_ADD, 0, 0,
	    &signal_handler);
	ctrl_handler = (struct kevcb){ &handle_ctrl, NULL };
	EV_MOD(kqfd, &kev, logger_cfd, EVFILT_READ, EV_ADD, 0, 0,
	    &ctrl_handler);
	pipe_handler = (struct kevcb){ &handle_pipe, NULL };
	EV_MOD(kqfd, &kev, pipefd, EVFILT_READ, EV_ADD, 0, 0, &pipe_handler);
	memset(&kev, 0, sizeof(kev));

	if (pledge("stdio", NULL) == -1)
		FATAL("pledge");

	while (kevent(kqfd, NULL, 0, &kev, 1, NULL) != -1)
		KEVENT_HANDLE(&kev);
	FATAL("kevent");
}

void
fork_logger(void)
{
	extern const struct procfunc	 process[];
	extern char			*__progname;

	int	 ctrlfd[2], ppfd[2];
	char	*argv[4];

	term_logger();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, ctrlfd) == -1)
		FATAL("socketpair");

	if (pipe(ppfd) == -1)
		FATAL("pipe");

	if ((logger_pid = fork()) == -1)
		FATAL("fork");

	if (logger_pid != 0) { /* parent */
		logger_cfd = ctrlfd[0];
		close(ctrlfd[1]);
		close(ppfd[0]);
		logfd = ppfd[1];
		dispatch_logger();
		return;
	}
	/* child */
	close(ctrlfd[0]);
	close(ppfd[1]);

	ITOE(ENV_CTRLFD, ctrlfd[1]);
	ITOE(ENV_LOGFD, ppfd[0]);

	argv[0] = process[PROC_LOGGER].name;
	argv[1] = __progname;
	argv[2] = conf->log;
	argv[3] = NULL;

	execvp(__progname, argv);
	FATAL("execvp");
}

void
kill_logger(void)
{
	term_logger();
	dispatch_logger();
}

static void
term_logger(void)
{
	extern int	 logger_pid;

	if (!logger_pid)
		return;

	kill(logger_pid, SIGUSR2);
	waitpid(logger_pid, NULL, 0);
	logger_pid = 0;
	close(logfd);
	logfd = -1;
	close(logger_cfd);
}

static void
dispatch_logger(void)
{
	extern pid_t	 sched_pid;
	extern int	 sched_cfd;

	struct target	*tgt;
	struct socket	*sock;

	sock = &conf->ctrlsock;
	if (sock->pid)
		send_logfd(sock->ctrlfd);
	STAILQ_FOREACH(tgt, &conf->ctargets, targets)
		STAILQ_FOREACH(sock, &tgt->datasocks, sockets)
			if (sock->pid)
				send_logfd(sock->ctrlfd);
	if (sched_pid)
		send_logfd(sched_cfd);
}

static void
send_logfd(int ctrlfd)
{
	enum msgtype	 mt;

	mt = logfd != -1 ? MSG_UPDATE_LOGFD : MSG_DELETE_LOGFD;

	SEND(ctrlfd, &mt, sizeof(mt));
	if (mt == MSG_UPDATE_LOGFD)
		while (send_fd(logfd, &mt, sizeof(mt), ctrlfd) == -1)
			NANONAP;
	/* wait for reply */
	RECV(ctrlfd, &mt, sizeof(mt));
	if (mt != MSG_ACK)
		FATALX("logfd update failed (%d)", mt);
}

void
recv_logfd(int ctrlfd)
{
	enum msgtype	 mt;

	if (logfd != -1)
		close(logfd);

	while ((logfd = recv_fd(&mt, sizeof(mt), ctrlfd)) == -1)
		NANONAP;
}

static void
plog_va(char *fmt, va_list args)
{
	extern int	 logfd;

	if (logfd == -1 && log_getdebug() == 0)
		return;

	vdprintf(logfd != -1 ? logfd : STDERR_FILENO, fmt, args);
}

void
print_log(char *fmt, ...)
{
	va_list	 args;

	va_start(args, fmt);
	plog_va(fmt, args);
	va_end(args);
}

void
print_ts_log(char *fmt, ...)
{
	struct timespec	 ts;
	struct tm	*tm;
	char		 buf[TS_SIZE];
	va_list		 args;

	GET_TIME(&ts);
	if ((tm = localtime(&ts.tv_sec)) == NULL)
		FATALX("localtime failed");
	if (strftime(buf, sizeof(buf), TS_FMT, tm) == 0)
		FATALX("strftime overflow");
	print_log("[%s] ", buf);

	va_start(args, fmt);
	plog_va(fmt, args);
	va_end(args);
}

void
append_data_log(char *buf, size_t size)
{
	char	*ptr = buf;

	while ((ptr = shift(ptr, buf, size)) != NULL)
		print_log("[%s]", ptr);

	print_log(".\n");
}
