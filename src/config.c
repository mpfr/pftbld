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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

#include "log.h"
#include "pftbld.h"

static int	 sockets_eq(struct socket *, struct socket *);
static struct socket
		*find_socket(struct socketq *, struct socket *);
static int	 check_targets(void);
static void	 update_sockets(struct socketq *, struct socketq *,
		    struct target *);
static char	*esc(const char *);

extern struct config	*conf;
extern struct clientq	 cltq;

static int
sockets_eq(struct socket *s1, struct socket *s2)
{
	return (!strcmp(s1->path, s2->path) && !strcmp(s1->id, s2->id) &&
	    s1->owner == s2->owner && s1->group == s2->group &&
	    s1->mode == s2->mode && s1->backlog == s2->backlog &&
	    s1->datamax == s2->datamax && s1->timeout == s2->timeout);
}

static struct socket *
find_socket(struct socketq *sockq, struct socket *sock)
{
	struct socket	*s;

	SIMPLEQ_FOREACH(s, sockq, sockets)
		if (sockets_eq(s, sock))
			return (s);

	return (NULL);
}

struct target *
find_target(struct targetq *tgtq, const char *name)
{
	struct target	*t;

	if (name == NULL || *name == '\0')
		return (NULL);

	SIMPLEQ_FOREACH(t, tgtq, targets)
		if (!strncmp(t->name, name, sizeof(t->name)))
			return (t);

	return (NULL);
}

int
parse_conf(void)
{
	extern FILE		*yyfp;
	extern int		 yyparse(void);
	extern int		 errors, lineno, colno;
	extern char		*conffile;
	extern struct crangeq	*curr_exclcrangeq;
	extern struct ptrq	*curr_exclkeytermq;

	struct crange	*self;
	struct target	*tgt;
	struct table	*tbl;
	struct socket	*sock;

	if ((yyfp = fopen(conffile, "r")) == NULL) {
		log_warnx("missing configuration file %s", conffile);
		return (1);
	}

	SIMPLEQ_INIT(&conf->ctargets);
	SIMPLEQ_INIT(&conf->exclcranges);
	SIMPLEQ_INIT(&conf->exclkeyterms);

	CALLOC(self, 1, sizeof(*self));
	SIMPLEQ_INSERT_HEAD(&conf->exclcranges, self, cranges);

	curr_exclcrangeq = &conf->exclcranges;
	curr_exclkeytermq = &conf->exclkeyterms;

	errors = lineno = colno = 0;
	yyparse();

	if (ferror(yyfp)) {
		log_warn("configuration file %s error", conffile);
		errors++;
	}
	if (fclose(yyfp) == EOF)
		log_warn("configuration file %s close", conffile);

	if (errors)
		return (errors);

	if (SIMPLEQ_EMPTY(&conf->ctargets)) {
		log_warnx("no targets defined in configuration file %s",
			conffile);
		errors++;
	}

	if (!conf->backlog) {
		conf->backlog = DEFAULT_BACKLOG;
		DPRINTF("using global default backlog (%d)", conf->backlog);
	}
	if (!conf->datamax) {
		conf->datamax = DEFAULT_DATAMAX;
		DPRINTF("using global default datamax (%lld)", conf->datamax);
	}
	if (!timespecisset(&conf->drop)) {
		conf->drop = TIMESPEC_INFINITE;
		DPRINTF("assuming no global drop");
	}
	if (!conf->timeout) {
		conf->timeout = DEFAULT_TIMEOUT;
		DPRINTF("using global default timeout (%lld)", conf->timeout);
	}

	sock = &conf->ctrlsock;
	sock->backlog = conf->backlog;
	sock->datamax = conf->datamax;
	sock->timeout = conf->timeout;

	if (*conf->log == '\0' && (conf->flags & FLAG_GLOBAL_NOLOG) == 0 &&
	    strlcpy(conf->log, LOG_FILE,
	    sizeof(conf->log)) >= sizeof(conf->log)) {
		log_warnx("default log file path '%s' too long", LOG_FILE);
		errors++;
	}

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		if (!timespecisset(&tgt->drop)) {
			tgt->drop = conf->drop;
#if DEBUG
			if (timespec_isinfinite(&conf->drop))
				DPRINTF("assuming no drop for target [%s]",
				    tgt->name);
			else
				DPRINTF("assuming global drop (%lld) for "
				    "target [%s]", tgt->drop.tv_sec,
				    tgt->name);
#endif
		}

		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets) {
			if (!sock->backlog) {
				sock->backlog = conf->backlog;
#if DEBUG
				if (sock->backlog == CONF_NO_BACKLOG)
					DPRINTF("assuming no backlog for "
					    "socket %s", sock->path);
				else
					DPRINTF("assuming socket %s backlog "
					    "(%d)", sock->path,
					    sock->backlog);
#endif
			}
			if (!sock->datamax) {
				sock->datamax = conf->datamax;
#if DEBUG
				if (sock->datamax == CONF_NO_DATAMAX)
					DPRINTF("assuming no datamax for "
					    "socket %s", sock->path);
				else
					DPRINTF("assuming socket %s datamax "
					    "(%lld)", sock->path,
					    sock->datamax);
#endif
			}
			if (!sock->timeout) {
				sock->timeout = conf->timeout;
#if DEBUG
				if (sock->timeout == CONF_NO_TIMEOUT)
					DPRINTF("assuming no timeout for "
					    "socket %s", sock->path);
				else
					DPRINTF("assuming socket %s timeout "
					    "(%lld)", sock->path,
					    sock->timeout);
#endif
			}
		}

		SIMPLEQ_FOREACH(tbl, &tgt->cascade, tables) {
			if (!timespecisset(&tbl->expire)) {
				tbl->expire = TIMESPEC_INFINITE;
				DPRINTF("assuming no expire for table <%s>",
				    tbl->name);
			}
			if (!timespecisset(&tbl->drop)) {
				tbl->drop = tgt->drop;
#if DEBUG
				if (timespec_isinfinite(&tgt->drop))
					DPRINTF("assuming no drop for "
					    "table <%s>", tbl->name);
				else
					DPRINTF("assuming target [%s] drop "
					    "(%lld) for table <%s>", tgt->name,
					    tbl->drop.tv_sec, tbl->name);
#endif
			}
			if (timespeccmp(&tbl->expire, &tbl->drop, >)) {
				log_warnx("target [%s]: table <%s> cannot "
				    "expire after drop", tgt->name, tbl->name);
				errors++;
				break;
			}
		}
	}

	return (errors);
}

static void
update_sockets(struct socketq *new, struct socketq *old, struct target *tgt)
{
	struct socket	*s, *st;

	if (old == NULL)
		goto new;

	SIMPLEQ_FOREACH(s, old, sockets) {
		st = new == NULL ? NULL : find_socket(new, s);
		if (st == NULL) {
			kill(s->pid, SIGUSR2);
			waitpid(s->pid, NULL, 0);
			if (unlink(s->path) == -1)
				log_warn("failed deleting socket %s", s->path);
			DPRINTF("socket (%s, %d, %d, %04o) deleted", s->path,
			    s->owner, s->group, s->mode);
		} else {
			st->pid = s->pid;
			st->ctrlfd = s->ctrlfd;
		}
	}

new:
	if (new == NULL)
		return;

	SIMPLEQ_FOREACH(s, new, sockets) {
		st = old == NULL ? NULL : find_socket(old, s);
		if (st == NULL) {
			fork_listener(s, tgt ? tgt->name : "");
			DPRINTF("socket (%s, %d, %d, %04o) created", s->path,
			    s->owner, s->group, s->mode);
		} else {
			s->pid = st->pid;
			s->ctrlfd = st->ctrlfd;
		}
	}
}

static int
check_targets(void)
{
	extern pid_t	 sched_pid;
	extern int	 sched_cfd;

	enum msgtype	 mt = MSG_CHECK_TARGETS;
	size_t		 len;
	int		 n;
	char		*buf, *buf2;
	struct target	*tgt;

	WRITE(sched_cfd, &mt, sizeof(mt));
	CALLOC(buf, 1, 1);
	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		buf2 = buf;
		ASPRINTF(&buf, "%s%s%s", buf2, strlen(buf2) > 0 ? "\n" : "",
		    tgt->name);
		free(buf2);
	}
	len = strlen(buf) + 1;
	WRITE2(sched_cfd, &len, sizeof(len), buf, len);
	free(buf);
	/* wait for reply */
	READ2(sched_cfd, &n, sizeof(n), &mt, sizeof(mt));
	if (mt != MSG_ACK)
		FATALX("invalid message type (%d)", mt);
	if (n > 0)
		log_warnx("%d client entr%s would be orphaned", n,
		    n != 1 ? "ies" : "y");
	return (n);
}

int
reload_conf(void)
{
	struct config	*confbak = conf;
	int		 c;
	struct target	*oldtgt, *newtgt;

	CALLOC(conf, 1, sizeof(*conf));

	if ((c = parse_conf()) > 0)
		goto fail;

	if (check_targets() > 0) {
		c = 1;
		goto fail;
	}

	conf->flags = confbak->flags;
	memcpy(&conf->ctrlsock, &confbak->ctrlsock, sizeof(struct socket));

	SIMPLEQ_FOREACH(oldtgt, &confbak->ctargets, targets)
		if (find_target(&conf->ctargets, oldtgt->name) == NULL) {
			DPRINTF("starting delete on target [%s]",
			    oldtgt->name);
			update_sockets(NULL, &oldtgt->datasocks, NULL);
			DPRINTF("finished deleting on target [%s]",
			    oldtgt->name);
		}
	SIMPLEQ_FOREACH(newtgt, &conf->ctargets, targets) {
		DPRINTF("starting update of target [%s]", newtgt->name);
		oldtgt = find_target(&confbak->ctargets, newtgt->name);
		update_sockets(&newtgt->datasocks,
		    oldtgt ? &oldtgt->datasocks : NULL, newtgt);
		DPRINTF("finished update of target [%s]", newtgt->name);
	}

	if ((conf->flags & FLAG_GLOBAL_NOLOG) != 0 &&
	    (confbak->flags & FLAG_GLOBAL_NOLOG) == 0) {
		DPRINTF("logger disabled");
		kill_logger();
	} else if ((conf->flags & FLAG_GLOBAL_NOLOG) == 0 &&
	    ((confbak->flags & FLAG_GLOBAL_NOLOG) != 0 ||
	    strcmp(confbak->log, conf->log))) {
#if DEBUG
		if ((confbak->flags & FLAG_GLOBAL_NOLOG) != 0)
			DPRINTF("logger enabled");
		else
			DPRINTF("logger reconfigured (%s -> %s)", confbak->log,
			    conf->log);
#endif
		fork_logger();
	}

	free_conf(confbak);
	return (0);

fail:
	log_warnx("%d configuration error%s found", c, c != 1 ? "s" : "");
	free_conf(conf);
	conf = confbak;
	return (c);
}

void
free_conf(struct config *c)
{
	struct target	*tgt;
	struct table	*tbl;
	struct socket	*sock;
	struct crange	*cr;
	struct ptr	*kt;

	while ((tgt = SIMPLEQ_FIRST(&c->ctargets)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&c->ctargets, targets);
		while ((sock = SIMPLEQ_FIRST(&tgt->datasocks)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&tgt->datasocks, sockets);
			free(sock);
		}
		while ((tbl = SIMPLEQ_FIRST(&tgt->cascade)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&tgt->cascade, tables);
			free(tbl);
		}
		while ((cr = SIMPLEQ_FIRST(&tgt->exclcranges)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&tgt->exclcranges, cranges);
			free(cr);
		}
		while ((kt = SIMPLEQ_FIRST(&tgt->exclkeyterms)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&tgt->exclkeyterms, ptrs);
			free(kt->p);
			free(kt);
		}
		free(tgt);
	}
	while ((cr = SIMPLEQ_FIRST(&c->exclcranges)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&c->exclcranges, cranges);
		free(cr);
	}
	while ((kt = SIMPLEQ_FIRST(&c->exclkeyterms)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&c->exclkeyterms, ptrs);
		free(kt->p);
		free(kt);
	}
	free(c);
}

static char *
esc(const char *str)
{
	const char	*s;
	char		*estr, *e;
	unsigned int	 cnt = 1; /* trailing nul */

	for (s = str; *s != '\0'; s++)
		if (*s == '\\' || *s == '"')
			cnt++;
	MALLOC(estr, s - str + cnt);
	for (s = str, e = estr; *s != '\0';) {
		if (*s == '\\' || *s == '"')
			*e++ = '\\';
		*e++ = *s++;
	}
	*e = '\0';
	return (estr);
}

void
print_conf(struct statfd *sfd)
{

#define SMSG(m)	"%s"m, step ? "\t" : ""

	char		*age, *estr, *ptbl;
	struct crange	*cr;
	struct ptr	*kt;
	struct target	*tgt;
	struct table	*tbl;
	struct timespec	 pexp;
	uint8_t		 pflgs;
	int		 step;
	struct socket	*sock;

	if (conf->backlog == CONF_NO_BACKLOG)
		msg_send(sfd, "no backlog\n");
	else
		msg_send(sfd, "backlog %d\n", conf->backlog);

	if (conf->datamax == CONF_NO_DATAMAX)
		msg_send(sfd, "no datamax\n");
	else
		msg_send(sfd, "datamax %lld\n", conf->datamax);

	if (timespeccmp(&conf->drop, &CONF_NO_DROP, ==))
		msg_send(sfd, "no drop\n");
	else {
		age = hrage(&conf->drop);
		msg_send(sfd, "drop %s\n", age);
		free(age);
	}

	cr = SIMPLEQ_FIRST(&conf->exclcranges);
	if ((cr != NULL && *cr->str != '\0') ||
	    !SIMPLEQ_EMPTY(&conf->exclkeyterms)) {
		msg_send(sfd, "exclude {\n");

		if (cr != NULL)
			while ((cr = SIMPLEQ_NEXT(cr, cranges)) != NULL)
				msg_send(sfd, "\tnet \"%s\"\n", cr->str);

		SIMPLEQ_FOREACH(kt, &conf->exclkeyterms, ptrs) {
			estr = esc(kt->p);
			msg_send(sfd, "\tkeyterm \"%s\"\n", estr);
			free(estr);
		}

		msg_send(sfd, "}\n");
	}

	if (conf->flags & FLAG_GLOBAL_NOLOG)
		msg_send(sfd, "no log\n");
	else {
		estr = esc(conf->log);
		msg_send(sfd, "log \"%s\"\n", estr);
		free(estr);
	}

	if (conf->timeout == CONF_NO_TIMEOUT)
		msg_send(sfd, "no timeout\n");
	else
		msg_send(sfd, "timeout %lld\n", conf->timeout);

	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		estr = esc(tgt->name);
		msg_send(sfd, "target \"%s\" {\n\tcascade {\n", estr);
		free(estr);

		step = 0;
		pexp = TIMESPEC_INFINITE;
		pflgs = DEFAULT_TABLE_KILL_FLAGS;
		ptbl = NULL;

		SIMPLEQ_FOREACH(tbl, &tgt->cascade, tables) {
			if (timespeccmp(&tgt->drop, &tbl->drop, !=)) {
				if (timespeccmp(&tbl->drop, &CONF_NO_DROP, ==))
					msg_send(sfd, SMSG("\t\tno drop\n"));
				else {
					age = hrage(&tbl->drop);
					msg_send(sfd, SMSG("\t\tdrop %s\n"),
					    age);
					free(age);
				}
			}

			if (!timespec_isinfinite(&tbl->expire) &&
			    timespeccmp(&pexp, &tbl->expire, !=)) {
				age = hrage(&tbl->expire);
				msg_send(sfd, SMSG("\t\texpire %s\n"), age);
				free(age);
			}

			if (tbl->hits)
				msg_send(sfd, SMSG("\t\thits %u\n"),
				    tbl->hits);

			if ((pflgs & FLAG_TABLE_KILL_NODES) !=
			    (tbl->flags & FLAG_TABLE_KILL_NODES))
				msg_send(sfd, SMSG("\t\t%s nodes\n"),
				    tbl->flags & FLAG_TABLE_KILL_NODES ?
				    "kill" : "keep");
			if ((pflgs & FLAG_TABLE_KILL_STATES) !=
			    (tbl->flags & FLAG_TABLE_KILL_STATES))
				msg_send(sfd, SMSG("\t\t%s states\n"),
				    tbl->flags & FLAG_TABLE_KILL_STATES ?
				    "kill" : "keep");

			if (ptbl == NULL || strcmp(ptbl, tbl->name)) {
				estr = esc(tbl->name);
				msg_send(sfd, SMSG("\t\ttable \"%s\"\n"),
				    estr);
				free(estr);
			}

			if (step)
				msg_send(sfd, "\t\t}\n");
			if (SIMPLEQ_NEXT(tbl, tables) != NULL) {
				msg_send(sfd, "\t\tstep {\n");
				step = 1;
			}

			pexp = tbl->expire;
			pflgs = tbl->flags;
			ptbl = tbl->name;
		}

		msg_send(sfd, "\t}\n");

		if (timespeccmp(&conf->drop, &tgt->drop, !=)) {
			if (timespeccmp(&tgt->drop, &CONF_NO_DROP, ==))
				msg_send(sfd, "\tno drop\n");
			else {
				age = hrage(&conf->drop);
				msg_send(sfd, "\tdrop %s\n", age);
				free(age);
			}
		}

		if (!SIMPLEQ_EMPTY(&tgt->exclcranges) ||
		    !SIMPLEQ_EMPTY(&tgt->exclkeyterms)) {
			msg_send(sfd, "\texclude {\n");

			SIMPLEQ_FOREACH(cr, &tgt->exclcranges, cranges)
				msg_send(sfd, "\t\tnet \"%s\"\n", cr->str);

			SIMPLEQ_FOREACH(kt, &tgt->exclkeyterms, ptrs) {
				estr = esc(kt->p);
				msg_send(sfd, "\t\tkeyterm \"%s\"\n", estr);
				free(estr);
			}

			msg_send(sfd, "\t}\n");
		}

		if (*tgt->persist != '\0') {
			estr = esc(tgt->persist);
			msg_send(sfd, "\tpersist \"%s\"\n", estr);
			free(estr);
		}

		if (tgt->skip > 0)
			msg_send(sfd, "\tskip %u\n", tgt->skip);

		SIMPLEQ_FOREACH(sock, &tgt->datasocks, sockets) {
			estr = esc(sock->path);
			msg_send(sfd, "\tsocket \"%s\" {\n", estr);
			free(estr);

			if (conf->backlog != sock->backlog) {
				if (sock->backlog == CONF_NO_BACKLOG)
					msg_send(sfd, "\t\tno backlog\n");
				else
					msg_send(sfd, "\t\tbacklog %d\n",
					    sock->backlog);
			}

			if (conf->datamax != sock->datamax) {
				if (sock->datamax == CONF_NO_DATAMAX)
					msg_send(sfd, "\t\tno datamax\n");
				else
					msg_send(sfd, "\t\tdatamax %lld\n",
					    sock->datamax);
			}

			msg_send(sfd, "\t\tgroup %d\n", sock->group);

			if (*sock->id != '\0') {
				estr = esc(sock->id);
				msg_send(sfd, "\t\tid \"%s\"\n", estr);
				free(estr);
			}

			msg_send(sfd, "\t\tmode %04o\n", sock->mode);

			msg_send(sfd, "\t\towner %d\n", sock->owner);

			if (conf->timeout != sock->timeout) {
				if (sock->timeout == CONF_NO_TIMEOUT)
					msg_send(sfd, "\t\tno timeout\n");
				else
					msg_send(sfd, "\t\ttimeout %lld\n",
					    sock->timeout);
			}

			msg_send(sfd, "\t}\n");

		}

		msg_send(sfd, "}\n");
	}

#undef SMSG

}
