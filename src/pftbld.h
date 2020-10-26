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

#include <limits.h>

#include <netinet/in.h>

#include <sys/event.h>
#include <sys/time.h>
#include <sys/un.h>

#define CONF_FILE	"/etc/pftbld/pftbld.conf"
#define SOCK_FILE	"/var/run/pftbld.sock"
#define LOG_FILE	"/var/log/pftbld.log"
#define PFTBLD_USER	"_pftbld"

#define DEFAULT_BACKLOG	5
#define DEFAULT_DATAMAX	2048
#define DEFAULT_TIMEOUT	10000

#define ENV_DEBUG	"DEBUG"
#define ENV_VERBOSE	"VERBOSE"
#define ENV_LOGFD	"LOGFD"
#define ENV_CTRLFD	"CTRLFD"
#define ENV_INBFD	"INBFD"
#define ENV_PRIVFD	"PRIVFD"

#define TS_FMT		"%d/%b/%Y:%H:%M:%S %z"
#define TS_SIZE		27

#define FLAG_GLOBAL_NOLOG	0x01
#define FLAG_GLOBAL_UNLOAD	0x02
#define FLAG_TABLE_KILL_STATES	0x01
#define FLAG_TABLE_KILL_NODES	0x02

#define	NANONAP	nanosleep(&(const struct timespec){ 0, 500000L }, NULL)

#define TIMESPEC_TO_MSEC(t)	((t)->tv_sec * 1000 + (t)->tv_nsec / 1000000L)
#define TIMESPEC_SEC_ROUND(t)	((t)->tv_nsec < 500000000L ? \
				    (t)->tv_sec : (t)->tv_sec + 1)
#define TIMESPEC_INFINITE	(const struct timespec){ LLONG_MAX, LONG_MAX }

#define timespec_isinfinite(t)	timespeccmp(t, &TIMESPEC_INFINITE, ==)

#define EV_DPRINTF(e, s)					\
	DPRINTF("KEVENT%s(id:%lu, EVFILT_%s%s, data:%lld)",	\
	    s ? "->" : "<-", (e)->ident,			\
	    (e)->filter == EVFILT_READ ? "READ" :		\
	    (e)->filter == EVFILT_TIMER ? "TIMER" :		\
	    (e)->filter == EVFILT_SIGNAL ? "SIGNAL" : "???",	\
	    s ? (e)->flags & EV_ADD ? "/ADD" :			\
	    (e)->flags & EV_DELETE ? "/DELETE" : "/???" : "",	\
	    (e)->data)

#define READ(d, b, n)				\
	do {					\
		if (read(d, b, n) == -1)	\
			FATAL("read");		\
	} while (0)

#define READ2(d, b1, n1, b2, n2)					\
	do {								\
		if (read(d, b1, n1) == -1 || read(d, b2, n2) == -1)	\
			FATAL("read");					\
	} while (0)

#define WRITE(d, b, n)				\
	do {					\
		if (write(d, b, n) == -1)	\
			FATAL("write");		\
	} while (0)

#define WRITE2(d, b1, n1, b2, n2)					\
	do {								\
		if (write(d, b1, n1) == -1 || write(d, b2, n2) == -1)	\
			FATAL("write");					\
	} while (0)

#define GETENV(s, e)							\
	do {								\
		if ((s = getenv(e)) == NULL)				\
			FATALX("environment variable '%s' not found", e); \
	} while (0)

#define SETENV(e, s)					\
	do {						\
		if (setenv(e, _s, 1) == -1)		\
			FATAL("setenv(%s, %s)", e, _s);	\
	} while (0)

#define LLTOS(s, n)					\
	do {						\
		if (asprintf(&s, "%lld", n) == -1)	\
			FATAL("asprintf");		\
	} while (0)

#define LLTOE(e, n)		\
	do {			\
		char	*_s;	\
		LLTOS(_s, n);	\
		SETENV(e, _s);	\
		free(_s);	\
	} while (0)

#define STOLL(n, s)							\
	do {								\
		const char	*_e;					\
		n = strtonum(s, LLONG_MIN, LLONG_MAX, &_e);		\
		if (_e != NULL)						\
			FATALX("strtonum(%s) failed: %s", s, _e);	\
	} while (0)

#define ETOLL(n, e)		\
	do {			\
		char	*_s;	\
		GETENV(_s, e);	\
		STOLL(n, _s);	\
	} while (0)

#define ITOS(s, n)					\
	do {						\
		if (asprintf(&s, "%d", n) == -1)	\
			FATAL("asprintf");		\
	} while (0)

#define ITOE(e, n)		\
	do {			\
		char	*_s;	\
		ITOS(_s, n);	\
		SETENV(e, _s);	\
		free(_s);	\
	} while (0)

#define FDTOE(e, d)				\
	do {					\
		int	 _dd;			\
		if ((_dd = dup(d)) == -1)	\
			FATAL("dup");		\
		ITOE(e, _dd);			\
	} while (0)

#define STOI(n, s)							\
	do {								\
		const char	*_e;					\
		n = strtonum(s, INT_MIN, INT_MAX, &_e);			\
		if (_e != NULL)						\
			FATALX("strtonum(%s) failed: %s", s, _e);	\
	} while (0)

#define ETOI(n, e)		\
	do {			\
		char	*_s;	\
		GETENV(_s, e);	\
		STOI(n, _s);	\
	} while (0)

#define EV_MOD(q, e, i, fi, fl, ff, d, u)			\
	do {							\
		EV_SET(e, i, fi, fl, ff, d, u);			\
		EV_DPRINTF(e, 1);				\
		if (kevent(q, e, 1, NULL, 0, NULL) == -1)	\
			FATAL("kevent");			\
	} while (0)

#define GET_TIME(t)						\
	do {							\
		if (clock_gettime(CLOCK_REALTIME, t) == -1)	\
			FATAL("clock_gettime");			\
	} while (0)

#define MALLOC(h, s)				\
	do {					\
		if ((h = malloc(s)) == NULL)	\
			FATAL("malloc");	\
	} while (0)

#define CALLOC(h, n, s)				\
	do {					\
		if ((h = calloc(n, s)) == NULL)	\
			FATAL("calloc");	\
	} while (0)

#define KEVENT_HANDLE(e)						\
	do {								\
		EV_DPRINTF(e, 0);					\
		if ((e)->flags & EV_ERROR)				\
			FATALX("event error (%lld)", (e)->data);	\
		if ((e)->udata != NULL) {				\
			struct kevcb *_h = (struct kevcb *)(e)->udata;	\
			(e)->udata = _h->args;				\
			_h->func(e);					\
		} else							\
			FATALX("unknown event (%lu, %hd)", (e)->ident,	\
			    (e)->filter);				\
	} while (0)

union addrvalue {
	struct in_addr	 ipv4;
	struct in6_addr	 ipv6;
};
enum addrtype { IPv4 = 1, IPv6 };

struct caddr {
	union addrvalue	 value;
	enum addrtype	 type;

	SIMPLEQ_ENTRY(caddr) caddrs;
};
SIMPLEQ_HEAD(caddrq, caddr);

struct crange {
	union addrvalue	 first;
	union addrvalue	 last;
	enum addrtype	 type;
	char		 str[INET6_ADDRSTRLEN + 4];

	SIMPLEQ_ENTRY(crange) cranges;
};
SIMPLEQ_HEAD(crangeq, crange);

struct keyterm {
	char	*str;

	SIMPLEQ_ENTRY(keyterm) keyterms;
};
SIMPLEQ_HEAD(keytermq, keyterm);

struct client {
	struct caddr	 addr;
	char		 astr[INET6_ADDRSTRLEN];
	unsigned int	 cnt;
	struct timespec	 ts;
	struct timespec	 to;
	struct table	*tbl;
	struct target	*tgt;
	int8_t		 exp;

	TAILQ_ENTRY(client) clients;
};
TAILQ_HEAD(clientq, client);

struct kevcb {
	void	 (*func)(struct kevent *);
	void	  *args;
};

struct inbuf {
	int		 datafd;
	char		 tgtname[NAME_MAX];
	char		 sockid[NAME_MAX];
	char		*data;
	size_t		 nr;
	size_t		 datamax;
	time_t		 timeout;
	struct kevcb	 handler;

	TAILQ_ENTRY(inbuf) inbufs;
};
TAILQ_HEAD(inbufq, inbuf);

struct table {
	char		 name[NAME_MAX];
	unsigned int	 hits;
	struct timespec	 expire;
	struct timespec	 drop;
	uint8_t		 flags;

	SIMPLEQ_ENTRY(table) tables;
};
SIMPLEQ_HEAD(tableq, table);

struct socket {
	char	 path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	char	 id[NAME_MAX];
	uid_t	 owner;
	gid_t	 group;
	mode_t	 mode;
	int	 backlog;
	size_t	 datamax;
	time_t	 timeout;
	pid_t	 pid;
	int	 ctrlfd;

	SIMPLEQ_ENTRY(socket) sockets;
};
SIMPLEQ_HEAD(socketq, socket);

struct target {
	char		 name[NAME_MAX];
	char		 persist[PATH_MAX];
	struct timespec	 drop;
	struct socketq	 datasocks;
	struct crangeq	 exclcranges;
	struct keytermq	 exclkeyterms;
	struct tableq	 cascade;

	SIMPLEQ_ENTRY(target) targets;
};
SIMPLEQ_HEAD(targetq, target);

struct config {
	struct socket	 ctrlsock;
	char		 log[PATH_MAX];
	int		 backlog;
	size_t		 datamax;
	time_t		 timeout;
	struct timespec	 drop;
	struct targetq	 ctargets;
	struct crangeq	 exclcranges;
	struct keytermq	 exclkeyterms;
	uint8_t		 flags;
};

struct pfresult {
	int	 nadd;
	int	 ndel;
	int	 nkill;
	int	 snkill;
};

struct pfaddrlist {
	char		 tblname[NAME_MAX];
	struct caddrq	 addrq;

	SIMPLEQ_ENTRY(pfaddrlist) pfaddrlists;
};
SIMPLEQ_HEAD(pfaddrlistq, pfaddrlist);

enum msgtype {
	NAK = -1,
	ACK,
	UPDATE_LOGFD,
	DELETE_LOGFD,
	CHECK_TARGETS,
	UPDATE_CONFIG,
	EXEC_PFCMD,
	HANDLE_PERSIST,
	SET_VERBOSE,
	CONF_RELOAD,
	QUEUE_NEXTITEM,
	QUEUE_ENDITEMS,
	INBUF_DONE,
	SHUTDOWN_MAIN
};

enum pathres {
	PATH_OK,
	PATH_EMPTY,
	PATH_RELATIVE,
	PATH_INVALID,
	PATH_DIRECTORY,
	PATH_FILENAME
};

/* pftbld.c */
void		 pfexec(struct caddrq *, struct pfresult *, const char *, ...)
		    __attribute__((__format__ (printf, 3, 4)));
__dead void	 pftbld(int, char **);

/* config.c */
struct target	*find_target(struct targetq *, const char *);
int		 parse_conf(void);
int		 reload_conf(void);
void		 free_conf(struct config *);

/* listener.c */
__dead void	 listener(int, char **);
void		 fork_listener(struct socket *, char *);
void		 proc_data(struct inbuf *, int);
void		 proc_ctrl(struct inbuf *);

/* logger.c */
__dead void	 logger(int, char **);
void		 fork_logger(void);
void		 kill_logger(void);
void		 recv_logfd(int);
void		 print_log(char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 print_ts_log(char *, ...)
		    __attribute__((__format__ (printf, 1, 2)));
void		 append_data_log(char *, size_t);

/* persist.c */
int		 save(struct target *);
int		 load(struct target *);

/* scheduler.c */
void		 sort_client_asc(struct client *);
void		 sort_client_desc(struct client *);
int		 drop_clients(const char *, struct target *);
int		 drop_clients_r(const char *, struct target *);
int		 expire_clients(const char *, struct target *);
int		 expire_clients_r(const char *, struct target *);
void		 handle_expire(struct kevent *);
__dead void	 scheduler(int, char **);
void		 fork_scheduler(void);
int		 bind_table(struct client *, struct pfaddrlistq *,
		    struct pfaddrlistq *);
void		 append_client(struct pfaddrlistq *, struct client *);
void		 apply_pfaddrlists(struct pfaddrlistq *, struct pfaddrlistq *);

/* sockpipe.c */
__dead void	 sockpipe(const char *, int);

/* tinypfctl.c */
__dead void	 tinypfctl(int, char **);
void		 fork_tinypfctl(struct pfresult *, char *, struct caddrq *,
		    size_t);

/* util.c */
void		 drop_priv(void);
int		 send_fd(int, void *, size_t, int);
int		 recv_fd(void *, size_t, int);
int		 parse_addr(struct caddr *, const char *);
int		 addr_inrange(struct crange *, struct caddr *);
int		 addrs_cmp(struct caddr *, struct caddr *);
int		 addrvals_cmp(union addrvalue *, union addrvalue *,
		    enum addrtype);
int		 cranges_eq(struct crange *, struct crange *);
char		*shift(char *, char *, size_t);
char		*replace(char *, const char *, const char);
char		*hrage(struct timespec *);
struct crange	*parse_crange(const char *);
char		*addrstr(char *, size_t, struct caddr *);
int		 prefill_socketopts(struct socket *);
enum pathres	 check_path(const char *, char *, size_t, char **);
