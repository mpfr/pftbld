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

#include <limits.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <netinet/in.h>

#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#define CONF_FILE	"/etc/pftbld/pftbld.conf"
#define SOCK_FILE	"/var/run/pftbld.sock"
#define LOG_FILE	"/var/log/pftbld.log"
#define PFTBLD_USER	"_pftbld"

#define DEFAULT_BACKLOG	5
#define DEFAULT_DATAMAX	2048
#define DEFAULT_TIMEOUT	10000
#define DEFAULT_SOCKMOD	0660

#define ENV_DEBUG	"DEBUG"
#define ENV_VERBOSE	"VERBOSE"
#define ENV_LOGFD	"LOGFD"
#define ENV_CTRLFD	"CTRLFD"
#define ENV_INBFD	"INBFD"
#define ENV_PRIVFD	"PRIVFD"

#define TS_FMT		"%d/%b/%Y:%H:%M:%S %z"
#define TS_SIZE		27
#define REPLY_ACK	"ACK\n"
#define REPLY_NAK	"NAK\n"
#define IGNORE_TIMEOUT	250

#define FLAG_GLOBAL_NOLOG		0x01
#define FLAG_GLOBAL_UNLOAD		0x02
#define FLAG_TABLE_KILL_STATES		0x01
#define FLAG_TABLE_KILL_NODES		0x02
#define DEFAULT_TABLE_KILL_FLAGS	FLAG_TABLE_KILL_STATES

#define	NANONAP	nanosleep(&(const struct timespec){ 0, 500000L }, NULL)

#define TIMESPEC_SEC_ROUND(t)	((t)->tv_sec + (t)->tv_nsec / 1000000000L + \
				    ((t)->tv_nsec % 1000000000L >= 500000000L))
#define TIMESPEC_TO_MSEC(t)	((t)->tv_sec * 1000 + (t)->tv_nsec / 1000000L)
#define TIMESPEC_INFINITE	(const struct timespec){ LLONG_MAX, LONG_MAX }
#define timespec_isinfinite(t)	timespeccmp(t, &TIMESPEC_INFINITE, ==)

#define CONF_NO_BACKLOG		-1
#define CONF_NO_DATAMAX		-1
#define CONF_DATAMAX_MAX	SSIZE_MAX
#define CONF_NO_TIMEOUT		-1
#define CONF_TIMEOUT_MAX	LLONG_MAX
#define CONF_NO_DROP		TIMESPEC_INFINITE
#define CONF_DROP_MAX		TIMESPEC_INFINITE.tv_sec

#define IOV_CNT(c)	((c) < IOV_MAX ? (c) : IOV_MAX)
#define PFADDR_MAX	(INT_MAX / sizeof(struct pfr_addr))
#define PFADDR_CNT(c)	((c) < PFADDR_MAX ? (c) : PFADDR_MAX)
#define PFADDR_LEN(c)	((c) * sizeof(struct pfr_addr))

#define FATALX_MSGTYPE(t)	FATALX("invalid message type (%d)", t)

#define CANONICAL_PATH_SET_0(str, path, txt, err, exit, ferr)	\
	do {							\
		switch (check_path(path, str, sizeof(str))) {	\
		case PATH_OK:					\
			break;					\
		case PATH_EMPTY:				\
			err("empty "txt" path");		\
			exit;					\
		case PATH_RELATIVE:				\
			err(txt" path cannot be relative");	\
			exit;					\
		case PATH_TRUNCATED:				\
			err(txt" path too long");		\
			exit;					\
		case PATH_DIRECTORY:				\
			err(txt" path cannot be a directory");	\
			exit;					\
		default:					\
			ferr;					\
		}						\
	} while (0)

#define CANONICAL_PATH_SET(str, path, txt, err, exit)	\
	CANONICAL_PATH_SET_0(str, path, txt, err, exit,	\
	    FATALX("internal path check error"))

#define EV_DPRINTF(e, s)					\
	DPRINTF("KEVENT%s(id:%lu, EVFILT_%s%s, data:%lld)",	\
	    s ? "->" : "<-", (e)->ident,			\
	    (e)->filter == EVFILT_READ ? "READ" :		\
	    (e)->filter == EVFILT_TIMER ? "TIMER" :		\
	    (e)->filter == EVFILT_SIGNAL ? "SIGNAL" : "???",	\
	    s ? (e)->flags & EV_ADD ? "/ADD" :			\
	    (e)->flags & EV_DELETE ? "/DELETE" : "/???" : "",	\
	    (e)->data)

#define STAILQ_MATCH(e, q, t, m)	\
	do {				\
		STAILQ_FOREACH(e, q, t)	\
			if (m)		\
				break;	\
	} while (0)

#define ASPRINTF(s, f, ...)					\
	do {							\
		if (asprintf(s, f, ##__VA_ARGS__) == -1)	\
			FATAL("asprintf");			\
	} while (0)

#define STRDUP(d, s)				\
	do {					\
		if ((d = strdup(s)) == NULL)	\
			FATAL("strdup");	\
	} while (0)

#define SEND(d, b, n)		send_data(d, b, n)
#define RECV(d, b, n)		recv_data(d, b, n)

#define ISEND(d, m, ...)	send_valist(d, m, __VA_ARGS__)
#define IRECV(d, m, ...)	recv_valist(d, m, __VA_ARGS__)

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

#define LLTOS(s, n)	ASPRINTF(&s, "%lld", n)

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

#define ITOS(s, n)	ASPRINTF(&s, "%d", n)

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
		if ((e)->udata == NULL)					\
			FATALX("unknown event (%lu, %hd)", (e)->ident,	\
			    (e)->filter);				\
		struct kevcb *_h = (struct kevcb *)(e)->udata;		\
		(e)->udata = _h->args;					\
		_h->func(e);						\
	} while (0)

#define PFCMD_INIT(c, i, t, f)			\
	do {					\
		(c)->id = i;			\
		(void)strlcpy((c)->tblname, t,	\
		    sizeof((c)->tblname));	\
		(c)->flags = f;			\
		STAILQ_INIT(&(c)->addrq);	\
	} while (0)

struct caddr {
	struct pfr_addr	 pfaddr;
	char		 str[INET6_ADDRSTRLEN];

	STAILQ_ENTRY(caddr) caddrs;
};
STAILQ_HEAD(caddrq, caddr);

union inaddr {
	struct in_addr	 ipv4;
	struct in6_addr	 ipv6;
};
struct crange {
	union inaddr	 first;
	union inaddr	 last;
	uint8_t		 af;
	char		 str[INET6_ADDRSTRLEN + 4];

	STAILQ_ENTRY(crange) cranges;
};
STAILQ_HEAD(crangeq, crange);

struct ptr {
	void	*p;

	STAILQ_ENTRY(ptr) ptrs;
};
STAILQ_HEAD(ptrq, ptr);

struct client {
	struct caddr	 addr;
	unsigned int	 hits;
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

struct table {
	char		 name[NAME_MAX];
	unsigned int	 hits;
	struct timespec	 expire;
	struct timespec	 drop;
	uint8_t		 flags;

	STAILQ_ENTRY(table) tables;
};
STAILQ_HEAD(tableq, table);

enum pfaction {
	ACTION_ADD = 0,
	ACTION_DELETE,
	ACTION_DROP
};
#define ACTION_TO_STR(a, s_add, s_delete, s_drop)	\
	(a == ACTION_ADD ? s_add :			\
	 a == ACTION_DELETE ? s_delete :		\
	 a == ACTION_DROP ? s_drop : "")
#define ACTION_TO_LSTR(a)	ACTION_TO_STR(a, "add", "delete", "drop")
#define ACTION_TO_CSTR(a)	ACTION_TO_STR(a, "Add", "Delete", "Drop")
#define ACTION_TO_LPSTR(a)	ACTION_TO_STR(a, "added", "deleted", "dropped")

struct socket {
	char		 path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	char		 id[NAME_MAX];
	uid_t		 owner;
	gid_t		 group;
	mode_t		 mode;
	int		 backlog;
	ssize_t		 datamax;
	time_t		 timeout;
	pid_t		 pid;
	int		 ctrlfd;
	enum pfaction	 action;

	STAILQ_ENTRY(socket) sockets;
};
STAILQ_HEAD(socketq, socket);

struct target {
	char		 name[NAME_MAX];
	char		 persist[PATH_MAX];
	struct timespec	 drop;
	unsigned int	 skip;
	struct socketq	 datasocks;
	struct crangeq	 exclcranges;
	struct ptrq	 exclkeyterms;
	struct crangeq	 inclcranges;
	struct ptrq	 inclkeyterms;
	struct tableq	 cascade;

	STAILQ_ENTRY(target) targets;
};
STAILQ_HEAD(targetq, target);

struct inbuf {
	int		 datafd;
	char		 tgtname[sizeof(((struct target *)0)->name)];
	char		 sockid[sizeof(((struct socket *)0)->id)];
	char		*data;
	ssize_t		 nr;
	ssize_t		 datamax;
	time_t		 timeout;
	struct kevcb	 handler;

	TAILQ_ENTRY(inbuf) inbufs;
};
TAILQ_HEAD(inbufq, inbuf);

struct config {
	struct socket	 ctrlsock;
	char		 log[PATH_MAX];
	int		 backlog;
	ssize_t		 datamax;
	time_t		 timeout;
	struct timespec	 drop;
	struct targetq	 ctargets;
	struct crangeq	 exclcranges;
	struct ptrq	 exclkeyterms;
	struct crangeq	 inclcranges;
	struct ptrq	 inclkeyterms;
	uint8_t		 flags;
};

struct pfresult {
	unsigned long	 nadd;
	unsigned long	 ndel;
	unsigned long	 nkill;
	unsigned long	 snkill;
};

enum pfcmdid { PFCMD_ADD = 1, PFCMD_DELETE };

struct pfcmd {
	enum pfcmdid	 id;
	char		 tblname[sizeof(((struct table *)0)->name)];
	uint8_t		 flags;
	unsigned long	 addrcnt;
	struct caddrq	 addrq;

	STAILQ_ENTRY(pfcmd) pfcmds;
};
STAILQ_HEAD(pfcmdq, pfcmd);

enum msgtype {
	MSG_NAK = -1,
	MSG_ACK,
	MSG_UPDATE_LOGFD,
	MSG_DELETE_LOGFD,
	MSG_CHECK_TARGETS,
	MSG_UPDATE_CONFIG,
	MSG_EXEC_PFCMD,
	MSG_HANDLE_PERSIST,
	MSG_SET_VERBOSE,
	MSG_CONF_RELOAD,
	MSG_QUEUE_NEXTITEM,
	MSG_QUEUE_ENDITEMS,
	MSG_INBUF_DONE,
	MSG_SHUTDOWN_MAIN
};

enum pathres {
	PATH_OK = 0,
	PATH_EMPTY,
	PATH_RELATIVE,
	PATH_TRUNCATED,
	PATH_DIRECTORY
};

struct procfunc {
	char		 *name;
	__dead void	(*call)(int, char **);
};

enum procid {
	PROC_PFTBLD = 0,
	PROC_LOGGER,
	PROC_SCHEDULER,
	PROC_LISTENER,
	PROC_TINYPFCTL,
	PROC_PERSIST,
	NUM_PROCS /* must be last */
};

struct statfd {
	int		 fd;
	struct stat	 sb;
};

struct ignore {
	struct caddr	 addr;
	char		*tgtname;
	char		*sockid;
	void		*ident;
	char		*data;
	unsigned int	 cnt;
	struct timespec	 ts;

	TAILQ_ENTRY(ignore) ignores;
};
TAILQ_HEAD(ignoreq, ignore);

/* pftbld.c */
void		 pfexec(struct pfresult *, struct pfcmd *);
__dead void	 pftbld(int, char **);

/* config.c */
struct target	*find_target_byname(struct targetq *, const char *);
struct socket	*find_socket_byid(struct socketq *, const char *);
int		 parse_conf(void);
int		 reload_conf(void);
void		 free_conf(struct config *);
void		 print_conf(struct statfd *);

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
__dead void	 persist(int, char **);
int		 fork_persist(char *);

/* scheduler.c */
void		 sort_client_asc(struct client *);
void		 sort_client_desc(struct client *);
unsigned int	 drop_clients(struct crangeq *, struct ptrq *);
unsigned int	 drop_clients_r(struct crangeq *, struct ptrq *);
unsigned int	 expire_clients(struct crangeq *, struct ptrq *);
unsigned int	 expire_clients_r(struct crangeq *, struct ptrq *);
struct ignore	*request_ignore(struct caddr *, char *, char *, void *);
void		 start_ignore(struct ignore *);
void		 cancel_ignore(struct ignore *);
__dead void	 scheduler(int, char **);
void		 fork_scheduler(void);
int		 bind_table(struct client *, struct pfcmdq *);
void		 apply_pfcmds(struct pfcmdq *);

/* sockpipe.c */
__dead void	 sockpipe(const char *, int);

/* tinypfctl.c */
__dead void	 tinypfctl(int, char **);
int		 fork_tinypfctl(struct pfcmd *);

/* util.c */
void		 drop_priv(void);
int		 send_fd(int, void *, size_t, int);
int		 recv_fd(void *, size_t, int);
void		 send_data(int, void *, size_t);
void		 recv_data(int, void *, size_t);
void		 send_valist(int, int, ...);
void		 recv_valist(int, int, ...);
int		 parse_addr(struct caddr *, const char *);
int		 addr_inrange(struct crange *, struct caddr *);
int		 addrs_cmp(struct caddr *, struct caddr *);
int		 addrvals_cmp(union inaddr *, union inaddr *, uint8_t);
int		 cranges_eq(struct crange *, struct crange *);
char		*shift(char *, char *, size_t);
char		*replace(char *, const char *, const char);
char		*hrage(struct timespec *);
struct crange	*parse_crange(const char *);
int		 prefill_socketopts(struct socket *);
enum pathres	 check_path(const char *, char *, size_t);
struct statfd	*create_statfd(int);
void		 msg_send(struct statfd *, const char *, ...)
		    __attribute__((__format__ (printf, 2, 3)));
