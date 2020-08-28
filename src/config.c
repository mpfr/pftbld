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
	extern struct keytermq	*curr_exclkeytermq;

	struct keytermq	 spq;
	struct keyterm	*spath;
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

	if (!timespecisset(&conf->drop)) {
		conf->drop = TIMESPEC_INFINITE;
		DPRINTF("assuming no global drop");
	}

	if (!conf->backlog) {
		conf->backlog = DEFAULT_BACKLOG;
		DPRINTF("using global default backlog (%d)", conf->backlog);
	}
	if (!conf->datamax) {
		conf->datamax = DEFAULT_DATAMAX;
		DPRINTF("using global default datamax (%zu)", conf->datamax);
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

	SIMPLEQ_INIT(&spq);
	MALLOC(spath, sizeof(*spath));
	spath->str = sock->path;
	SIMPLEQ_INSERT_HEAD(&spq, spath, keyterms);

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
			spath = SIMPLEQ_FIRST(&spq);
			while (spath != NULL) {
				if (!strcmp(spath->str, sock->path)) {
					log_warnx("socket path %s repeatedly "
					    "defined on target [%s%s]",
					    sock->path, tgt->name, sock->id);
					errors++;
					break;
				}
				spath = SIMPLEQ_NEXT(spath, keyterms);
			}
			if (spath == NULL) {
				MALLOC(spath, sizeof(*spath));
				spath->str = sock->path;
				SIMPLEQ_INSERT_TAIL(&spq, spath, keyterms);
			}
			if (!sock->backlog) {
				sock->backlog = conf->backlog;
#if DEBUG
				if (sock->backlog == INT_MAX)
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
				if (sock->datamax == LONG_MAX)
					DPRINTF("assuming no datamax for "
					    "socket %s", sock->path);
				else
					DPRINTF("assuming socket %s datamax "
					    "(%zu)", sock->path,
					    sock->datamax);
#endif
			}
			if (!sock->timeout) {
				sock->timeout = conf->timeout;
#if DEBUG
				if (sock->timeout == LLONG_MAX)
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
			}
		}
	}

	while ((spath = SIMPLEQ_FIRST(&spq)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&spq, keyterms);
		free(spath);
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
			kill(s->pid, SIGINT);
			waitpid(s->pid, NULL, 0);
			if (unlink(s->path) == -1)
				log_warn("failed deleting socket %s", s->path);
			DPRINTF("socket (%s, %d, %d, %03o) deleted", s->path,
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
			DPRINTF("socket (%s, %d, %d, %03o) created", s->path,
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

	enum msgtype	 mt = CHECK_TARGETS;
	size_t		 len;
	int		 n;
	char		*buf, *buf2;
	struct target	*tgt;

	WRITE(sched_cfd, &mt, sizeof(mt));
	CALLOC(buf, 1, 1);
	SIMPLEQ_FOREACH(tgt, &conf->ctargets, targets) {
		buf2 = buf;
		if (asprintf(&buf, "%s%s%s", buf2,
		    strlen(buf2) > 0 ? "\n" : "", tgt->name) == -1)
			FATAL("asprintf");
		free(buf2);
	}
	len = strlen(buf) + 1;
	WRITE2(sched_cfd, &len, sizeof(len), buf, len);
	free(buf);
	/* wait for reply */
	READ2(sched_cfd, &n, sizeof(n), &mt, sizeof(mt));
	if (mt != ACK)
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
	struct keyterm	*kt;

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
			SIMPLEQ_REMOVE_HEAD(&tgt->exclkeyterms, keyterms);
			free(kt->str);
			free(kt);
		}
		free(tgt);
	}
	while ((cr = SIMPLEQ_FIRST(&c->exclcranges)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&c->exclcranges, cranges);
		free(cr);
	}
	while ((kt = SIMPLEQ_FIRST(&c->exclkeyterms)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&c->exclkeyterms, keyterms);
		free(kt->str);
		free(kt);
	}
	free(c);
}
