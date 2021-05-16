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

	STAILQ_FOREACH(s, sockq, sockets)
		if (sockets_eq(s, sock))
			return (s);

	return (NULL);
}

struct target *
find_target_byname(struct targetq *tgtq, const char *name)
{
	struct target	*t;

	if (name == NULL || *name == '\0')
		return (NULL);

	STAILQ_MATCH(t, tgtq, targets,
	    !strncmp(t->name, name, sizeof(t->name)));

	return (t);
}

struct socket *
find_socket_byid(struct socketq *sockq, const char *id)
{
	struct socket	*s;

	if (id == NULL)
		return (NULL);

	STAILQ_MATCH(s, sockq, sockets, !strncmp(s->id, id, sizeof(s->id)));

	return (s);
}

int
parse_conf(void)
{
	extern FILE		*yyfp;
	extern int		 yyparse(void);
	extern int		 errors, lineno, colno;
	extern char		 conffile[PATH_MAX];
	extern struct crangeq	*curr_exclcrangeq, *curr_inclcrangeq;
	extern struct ptrq	*curr_exclkeytermq, *curr_inclkeytermq;

	struct crange	*self;
	struct target	*tgt;
	struct table	*tbl;
	struct socket	*sock;

	if ((yyfp = fopen(conffile, "r")) == NULL) {
		log_warnx("missing configuration file %s", conffile);
		return (1);
	}

	STAILQ_INIT(&conf->ctargets);
	STAILQ_INIT(&conf->exclcranges);
	STAILQ_INIT(&conf->exclkeyterms);
	STAILQ_INIT(&conf->inclcranges);
	STAILQ_INIT(&conf->inclkeyterms);

	CALLOC(self, 1, sizeof(*self));
	STAILQ_INSERT_HEAD(&conf->exclcranges, self, cranges);

	curr_exclcrangeq = &conf->exclcranges;
	curr_exclkeytermq = &conf->exclkeyterms;
	curr_inclcrangeq = &conf->inclcranges;
	curr_inclkeytermq = &conf->inclkeyterms;

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

	if (STAILQ_EMPTY(&conf->ctargets)) {
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
		DPRINTF("using global default datamax (%zd)", conf->datamax);
	}
	if (!timespecisset(&conf->drop)) {
		conf->drop = TIMESPEC_INFINITE;
		DPRINTF("assuming no global drop");
	}
	if (!conf->idlemin) {
		conf->idlemin = DEFAULT_IDLEMIN;
		DPRINTF("using global default idlemin (%d)", conf->idlemin);
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

	STAILQ_FOREACH(tgt, &conf->ctargets, targets) {
		if (!timespecisset(&tgt->drop)) {
			tgt->drop = conf->drop;
#if DEBUG
			if (timespec_isinfinite(&conf->drop))
				DPRINTF("assuming global no drop for "
				    "target [%s]", tgt->name);
			else
				DPRINTF("assuming global drop (%lld) for "
				    "target [%s]", tgt->drop.tv_sec,
				    tgt->name);
#endif
		}

		if (!tgt->idlemin) {
			tgt->idlemin = conf->idlemin;
#if DEBUG
			if (tgt->idlemin == CONF_NO_IDLEMIN)
				DPRINTF("assuming global no idlemin for "
				    "target [%s]", tgt->name);
			else
				DPRINTF("assuming global idlemin (%d) for "
				    "target [%s]", tgt->idlemin, tgt->name);
#endif
		}

		STAILQ_FOREACH(sock, &tgt->datasocks, sockets) {
			if (!sock->backlog) {
				sock->backlog = conf->backlog;
#if DEBUG
				if (sock->backlog == CONF_NO_BACKLOG)
					DPRINTF("assuming global no backlog "
					    "for socket %s", sock->path);
				else
					DPRINTF("assuming global backlog (%d) "
					    "for socket %s", sock->backlog,
					    sock->path);
#endif
			}
			if (!sock->datamax) {
				sock->datamax = conf->datamax;
#if DEBUG
				if (sock->datamax == CONF_NO_DATAMAX)
					DPRINTF("assuming global no datamax "
					    "for socket %s", sock->path);
				else
					DPRINTF("assuming global datamax "
					    "(%zd) socket %s", sock->datamax,
					    sock->path);
#endif
			}
			if (!sock->timeout) {
				sock->timeout = conf->timeout;
#if DEBUG
				if (sock->timeout == CONF_NO_TIMEOUT)
					DPRINTF("assuming global no timeout "
					    "for socket %s", sock->path);
				else
					DPRINTF("assuming global timeout "
					    "(%lld) socket %s", sock->timeout,
					    sock->path);
#endif
			}
		}

		STAILQ_FOREACH(tbl, &tgt->cascade, tables) {
			if (!timespecisset(&tbl->expire)) {
				tbl->expire = TIMESPEC_INFINITE;
				DPRINTF("assuming no expire for table <%s>",
				    tbl->name);
			}
			if (!timespecisset(&tbl->drop)) {
				tbl->drop = tgt->drop;
#if DEBUG
				if (timespec_isinfinite(&tbl->drop))
					DPRINTF("assuming target [%s] no drop "
					    "for table <%s>", tgt->name,
					    tbl->name);
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
			if (!timespec_isinfinite(&tbl->expire) &&
			    tgt->idlemin > TIMESPEC_TO_MSEC(&tbl->expire)) {
				log_warnx("target [%s]: expire of table <%s> "
				    "must not be less than idlemin",
				    tgt->name, tbl->name);
				errors++;
				break;
			}
			if (!timespec_isinfinite(&tbl->drop) &&
			    tgt->idlemin > TIMESPEC_TO_MSEC(&tbl->drop)) {
				log_warnx("target [%s]: drop of table <%s> "
				    "must not be less than idlemin",
				    tgt->name, tbl->name);
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

	STAILQ_FOREACH(s, old, sockets) {
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

	STAILQ_FOREACH(s, new, sockets) {
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

	CALLOC(buf, 1, 1);
	STAILQ_FOREACH(tgt, &conf->ctargets, targets) {
		buf2 = buf;
		ASPRINTF(&buf, "%s%s%s", buf2, strlen(buf2) > 0 ? "\n" : "",
		    tgt->name);
		free(buf2);
	}
	len = strlen(buf) + 1;
	ISEND(sched_cfd, 3, &mt, sizeof(mt), &len, sizeof(len), buf, len);
	free(buf);
	/* wait for reply */
	IRECV(sched_cfd, 2, &n, sizeof(n), &mt, sizeof(mt));
	if (mt != MSG_ACK)
		FATALX_MSGTYPE(mt);
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

	STAILQ_FOREACH(oldtgt, &confbak->ctargets, targets)
		if (find_target_byname(&conf->ctargets,
		    oldtgt->name) == NULL) {
			DPRINTF("starting delete on target [%s]",
			    oldtgt->name);
			update_sockets(NULL, &oldtgt->datasocks, NULL);
			DPRINTF("finished deleting on target [%s]",
			    oldtgt->name);
		}
	STAILQ_FOREACH(newtgt, &conf->ctargets, targets) {
		DPRINTF("starting update of target [%s]", newtgt->name);
		oldtgt = find_target_byname(&confbak->ctargets, newtgt->name);
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

	while ((tgt = STAILQ_FIRST(&c->ctargets)) != NULL) {
		STAILQ_REMOVE_HEAD(&c->ctargets, targets);
		while ((sock = STAILQ_FIRST(&tgt->datasocks)) != NULL) {
			STAILQ_REMOVE_HEAD(&tgt->datasocks, sockets);
			free(sock);
		}
		while ((tbl = STAILQ_FIRST(&tgt->cascade)) != NULL) {
			STAILQ_REMOVE_HEAD(&tgt->cascade, tables);
			free(tbl);
		}
		while ((cr = STAILQ_FIRST(&tgt->exclcranges)) != NULL) {
			STAILQ_REMOVE_HEAD(&tgt->exclcranges, cranges);
			free(cr);
		}
		while ((kt = STAILQ_FIRST(&tgt->exclkeyterms)) != NULL) {
			STAILQ_REMOVE_HEAD(&tgt->exclkeyterms, ptrs);
			free(kt->p);
			free(kt);
		}
		while ((cr = STAILQ_FIRST(&tgt->inclcranges)) != NULL) {
			STAILQ_REMOVE_HEAD(&tgt->inclcranges, cranges);
			free(cr);
		}
		while ((kt = STAILQ_FIRST(&tgt->inclkeyterms)) != NULL) {
			STAILQ_REMOVE_HEAD(&tgt->inclkeyterms, ptrs);
			free(kt->p);
			free(kt);
		}
		free(tgt->idlehandler.args);
		free(tgt);
	}
	while ((cr = STAILQ_FIRST(&c->exclcranges)) != NULL) {
		STAILQ_REMOVE_HEAD(&c->exclcranges, cranges);
		free(cr);
	}
	while ((kt = STAILQ_FIRST(&c->exclkeyterms)) != NULL) {
		STAILQ_REMOVE_HEAD(&c->exclkeyterms, ptrs);
		free(kt->p);
		free(kt);
	}
	while ((cr = STAILQ_FIRST(&c->inclcranges)) != NULL) {
		STAILQ_REMOVE_HEAD(&c->inclcranges, cranges);
		free(cr);
	}
	while ((kt = STAILQ_FIRST(&c->inclkeyterms)) != NULL) {
		STAILQ_REMOVE_HEAD(&c->inclkeyterms, ptrs);
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
		msg_send(sfd, "datamax %zd\n", conf->datamax);

	if (timespeccmp(&conf->drop, &CONF_NO_DROP, ==))
		msg_send(sfd, "no drop\n");
	else {
		age = hrage(&conf->drop);
		msg_send(sfd, "drop %s\n", age);
		free(age);
	}

	cr = STAILQ_FIRST(&conf->exclcranges); /* self-exclude */
	if ((cr = STAILQ_NEXT(cr, cranges)) != NULL ||
	    !STAILQ_EMPTY(&conf->exclkeyterms)) {
		msg_send(sfd, "exclude {\n");

		while (cr != NULL) {
			msg_send(sfd, "\tnet \"%s\"\n", cr->str);
			cr = STAILQ_NEXT(cr, cranges);
		}

		STAILQ_FOREACH(kt, &conf->exclkeyterms, ptrs) {
			estr = esc(kt->p);
			msg_send(sfd, "\tkeyterm \"%s\"\n", estr);
			free(estr);
		}

		msg_send(sfd, "}\n");
	}

	if (conf->idlemin == CONF_NO_IDLEMIN)
		msg_send(sfd, "no idlemin\n");
	else
		msg_send(sfd, "idlemin %d\n", conf->idlemin);

	if (!STAILQ_EMPTY(&conf->inclcranges) ||
	    !STAILQ_EMPTY(&conf->inclkeyterms)) {
		msg_send(sfd, "include {\n");

		STAILQ_FOREACH(cr, &conf->inclcranges, cranges)
			msg_send(sfd, "\tnet \"%s\"\n", cr->str);

		STAILQ_FOREACH(kt, &conf->inclkeyterms, ptrs) {
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

	STAILQ_FOREACH(tgt, &conf->ctargets, targets) {
		estr = esc(tgt->name);
		msg_send(sfd, "target \"%s\" {\n\tcascade {\n", estr);
		free(estr);

		step = 0;
		pexp = TIMESPEC_INFINITE;
		pflgs = DEFAULT_TABLE_KILL_FLAGS;
		ptbl = NULL;

		STAILQ_FOREACH(tbl, &tgt->cascade, tables) {
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
			if (STAILQ_NEXT(tbl, tables) != NULL) {
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

		if (!STAILQ_EMPTY(&tgt->exclcranges) ||
		    !STAILQ_EMPTY(&tgt->exclkeyterms)) {
			msg_send(sfd, "\texclude {\n");

			STAILQ_FOREACH(cr, &tgt->exclcranges, cranges)
				msg_send(sfd, "\t\tnet \"%s\"\n", cr->str);

			STAILQ_FOREACH(kt, &tgt->exclkeyterms, ptrs) {
				estr = esc(kt->p);
				msg_send(sfd, "\t\tkeyterm \"%s\"\n", estr);
				free(estr);
			}

			msg_send(sfd, "\t}\n");
		}

		if (conf->idlemin != tgt->idlemin) {
			if (tgt->idlemin == CONF_NO_IDLEMIN)
				msg_send(sfd, "\tno idlemin\n");
			else
				msg_send(sfd, "\tidlemin %d\n", tgt->idlemin);
		}

		if (!STAILQ_EMPTY(&tgt->inclcranges) ||
		    !STAILQ_EMPTY(&tgt->inclkeyterms)) {
			msg_send(sfd, "\tinclude {\n");

			STAILQ_FOREACH(cr, &tgt->inclcranges, cranges)
				msg_send(sfd, "\t\tnet \"%s\"\n", cr->str);

			STAILQ_FOREACH(kt, &tgt->inclkeyterms, ptrs) {
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

		STAILQ_FOREACH(sock, &tgt->datasocks, sockets) {
			estr = esc(sock->path);
			msg_send(sfd, "\tsocket \"%s\" {\n", estr);
			free(estr);

			msg_send(sfd, "\t\taction %s\n",
			    ACTION_TO_LSTR(sock->action));

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
					msg_send(sfd, "\t\tdatamax %zd\n",
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
