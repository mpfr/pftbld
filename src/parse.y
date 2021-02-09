/*
 * Copyright (c) 2020, 2021 Matthias Pressfreund
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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

%{
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>

#include "log.h"
#include "pftbld.h"

#define NUMROWS(tbl)	(sizeof(tbl) / sizeof(tbl[0]))

#define HOSTS_FILE	"/etc/hosts"

#define YY_CANONICAL_PATH_SET(str, path, txt, err, exit)	\
	CANONICAL_PATH_SET(str, path, txt, err yyerror, exit)

static void	yyerror(const char *, ...);
static int	yylex(void);

static int	 load_exclude_keyterms(const char *);
static int	 crange_inq(struct crangeq *, struct crange *);
static int	 keyterm_inq(struct ptrq *, struct ptr *);
static int	 load_exclude_cranges(const char *);

typedef struct {
	union {
		char		*string;
		long long	 number;
		time_t		 time;
	} v;
} YYSTYPE;

FILE		*yyfp;
struct config	*conf;
int		 errors, lineno, colno;

static struct target	*target;
static struct socket	*sock;
static struct table	*table, *ptable;
static uint8_t		 flags;

struct crangeq	*curr_exclcrangeq;
struct ptrq	*curr_exclkeytermq;

%}

%token	ACTION ADD BACKLOG CASCADE DATAMAX DELETE DROP EXCLUDE EXPIRE GROUP
%token	HITS ID KEEP KEYTERM KEYTERMFILE KILL LOCALHOSTS LOG MODE NET NETFILE
%token	NO NODES OWNER PERSIST SKIP SOCKET STATES STEP TABLE TARGET TIMEOUT
%token	<v.number>	NUMBER
%token	<v.string>	STRING
%token	<v.time>	TIME

%%

grammar		: /* empty */
		| grammar '\n'
		| grammar main '\n'
		;

main		: BACKLOG NUMBER		{
			if ($2 <= 0 || $2 > CONF_BACKLOG_MAX) {
				yyerror("backlog out of bounds");
				YYERROR;
			}
			conf->backlog = $2;
			DPRINTF("global backlog: %d", conf->backlog);
		}
		| DATAMAX NUMBER		{
			if ($2 <= 0 || $2 > CONF_DATAMAX_MAX) {
				yyerror("datamax out of bounds");
				YYERROR;
			}
			conf->datamax = $2;
			DPRINTF("global datamax: %zd", conf->datamax);
		}
		| DROP TIME			{
			if ($2 <= 0 || $2 > CONF_DROP_MAX) {
				yyerror("drop time out of bounds");
				YYERROR;
			}
			conf->drop.tv_sec = $2;
			DPRINTF("global drop time: %lld", conf->drop.tv_sec);
		}
		| exclude
		| LOG STRING			{
			YY_CANONICAL_PATH_SET(conf->log, $2, "log file",
			    free($2);, YYERROR);
			free($2);
			conf->flags &= ~FLAG_GLOBAL_NOLOG;
			DPRINTF("log file is %s, flags: %02X", conf->log,
			    conf->flags);
		}
		| NO BACKLOG			{
			conf->backlog = CONF_NO_BACKLOG;
			DPRINTF("no global backlog");
		}
		| NO DATAMAX			{
			conf->datamax = CONF_NO_DATAMAX;
			DPRINTF("no global datamax");
		}
		| NO DROP			{
			conf->drop = CONF_NO_DROP;
			DPRINTF("no global drop");
		}
		| NO LOG			{
			conf->flags |= FLAG_GLOBAL_NOLOG;
			DPRINTF("no log, flags: %02X", conf->flags);
		}
		| NO TIMEOUT			{
			conf->timeout = CONF_NO_TIMEOUT;
			DPRINTF("no global timeout");
		}
		| TIMEOUT NUMBER		{
			if ($2 <= 0 || $2 > CONF_TIMEOUT_MAX) {
				yyerror("timeout out of bounds");
				YYERROR;
			}
			conf->timeout = $2;
			DPRINTF("global timeout: %lld", conf->timeout);
		}
		| TARGET STRING			{
			SIMPLEQ_FOREACH(target, &conf->ctargets, targets)
				if (!strncmp(target->name, $2,
				    sizeof(target->name))) {
					free($2);
					yyerror("target defined twice");
					YYERROR;
				}
			CALLOC(target, 1, sizeof(*target));
			SIMPLEQ_INSERT_TAIL(&conf->ctargets, target, targets);
			if (strlcpy(target->name, $2,
			    sizeof(target->name)) >= sizeof(target->name)) {
				free($2);
				yyerror("target name too long");
				YYERROR;
			}
			free($2);
			SIMPLEQ_INIT(&target->datasocks);
			SIMPLEQ_INIT(&target->exclcranges);
			SIMPLEQ_INIT(&target->exclkeyterms);
			SIMPLEQ_INIT(&target->cascade);
			DPRINTF("current target is [%s]", target->name);
			curr_exclcrangeq = &target->exclcranges;
			curr_exclkeytermq = &target->exclkeyterms;
		} '{' optnl targetopts_l '}'	{
			if (SIMPLEQ_EMPTY(&target->datasocks)) {
				yyerror("no sockets defined for target [%s]",
				    target->name);
				YYERROR;
			}
			if (SIMPLEQ_EMPTY(&target->cascade)) {
				yyerror("no cascade defined for target [%s]",
				    target->name);
				YYERROR;
			}
			curr_exclcrangeq = &conf->exclcranges;
			curr_exclkeytermq = &conf->exclkeyterms;
		}
		;

targetopts_l	: targetopts_l targetoptsl nl
		| targetoptsl optnl
		;

targetoptsl	: CASCADE			{
			if (!SIMPLEQ_EMPTY(&target->cascade)) {
				yyerror("second cascade not permitted");
				YYERROR;
			}
			CALLOC(table, 1, sizeof(*table));
			SIMPLEQ_INSERT_HEAD(&target->cascade, table, tables);
			DPRINTF("top cascade table enqueued");
			ptable = table;
			table->flags = DEFAULT_TABLE_KILL_FLAGS;
		} '{' optnl cascadeopts_l '}'	{
			struct table	*t, *nt;
			unsigned int	 n;

			t = SIMPLEQ_FIRST(&target->cascade);
			if (*t->name == '\0') {
				yyerror("missing cascade head table");
				YYERROR;
			}
			for (n = 1;
			    (nt = SIMPLEQ_NEXT(t, tables)) != NULL; n++) {
				if (t->hits == 0) {
					yyerror("cascade step %u unreachable",
					    n);
					YYERROR;
				}
				if (nt->hits == 0)
					DPRINTF("cascade closed by step %u", n);
				else if (nt->hits <= t->hits) {
					yyerror("cascade step %u must catch "
					    "more than %u hit%s", n, t->hits,
					    t->hits > 1 ? "s" : "");
					YYERROR;
				}
				if (*nt->name != '\0') {
					t = nt;
					continue;
				}
				if (nt->flags == t->flags &&
				    timespeccmp(&nt->drop, &t->drop, ==) &&
				    timespeccmp(&nt->expire, &t->expire, ==)) {
					t->hits = nt->hits;
					SIMPLEQ_REMOVE_AFTER(&target->cascade,
					    t, tables);
					free(nt);
					DPRINTF("merged upwards %u hit%s from "
					    "cascade step %u", nt->hits,
					    nt->hits > 1 ? "s" : "", n);
					continue;
				}
				(void)strlcpy(nt->name, t->name,
				    sizeof(nt->name));
				DPRINTF("step %u inherited table name <%s>", n,
				    nt->name);
				t = nt;
			}
			if (t->hits > 0) {
				yyerror("open cascade after %u hit%s", t->hits,
				    t->hits > 1 ? "s" : "");
				YYERROR;
			}
		}
		| DROP TIME			{
			if ($2 <= 0 || $2 > CONF_DROP_MAX) {
				yyerror("drop time out of bounds");
				YYERROR;
			}
			target->drop.tv_sec = $2;
			DPRINTF("drop time: %lld", target->drop.tv_sec);
		}
		| exclude
		| NO DROP			{
			target->drop = CONF_NO_DROP;
			DPRINTF("no drop");
		}
		| PERSIST STRING		{
			YY_CANONICAL_PATH_SET(target->persist, $2,
			    "persist file", free($2);, YYERROR);
			free($2);
			DPRINTF("persist file: %s", target->persist);
		}
		| SKIP NUMBER			{
			if ($2 <= 0 || $2 > UINT_MAX) {
				yyerror("skip number out of bounds");
				YYERROR;
			}
			target->skip = $2;
			DPRINTF("skip: %u", target->skip);
		}
		| SOCKET STRING			{
			struct target	*t;
			struct socket	*s;

			CALLOC(sock, 1, sizeof(*sock));
			YY_CANONICAL_PATH_SET(sock->path, $2, "socket",
			    free($2); free(sock);, YYERROR);
			free($2);
			if ((s = SIMPLEQ_FIRST(&target->datasocks)) != NULL &&
			    *s->id == '\0') {
				free(sock);
				yyerror("no more sockets allowed as first "
				    "socket has no id");
				YYERROR;
			}
			if (!strcmp(conf->ctrlsock.path, sock->path)) {
				free(sock);
				yyerror("attempt to overwrite control socket");
				YYERROR;
			}
			SIMPLEQ_FOREACH(t, &conf->ctargets, targets)
				SIMPLEQ_FOREACH(s, &t->datasocks, sockets) {
					if (strcmp(s->path, sock->path))
						continue;
					free(sock);
					yyerror("socket path defined twice");
					YYERROR;
				}
			if (prefill_socketopts(sock) == -1) {
				free(sock);
				yyerror("prefill socket options failed");
				YYERROR;
			}
			SIMPLEQ_INSERT_TAIL(&target->datasocks, sock, sockets);
			DPRINTF("current data socket at %s", sock->path);
		} sockopts			{
			struct target	*t;
			struct socket	*s;
			char		*i0, *i1;

			if (*sock->id == '\0' &&
			    sock != SIMPLEQ_FIRST(&target->datasocks)) {
				yyerror("socket requires id");
				YYERROR;
			}
			ASPRINTF(&i0, "%s%s", target->name, sock->id);
			SIMPLEQ_FOREACH(t, &conf->ctargets, targets)
				SIMPLEQ_FOREACH(s, &t->datasocks, sockets) {
					if (s == sock)
						continue;
					ASPRINTF(&i1, "%s%s", t->name, s->id);
					if (strcmp(i0, i1)) {
						free(i1);
						continue;
					}
					free(i1);
					free(i0);
					yyerror("combination of target name "
					    "and socket id defined twice");
					YYERROR;
				}
			free(i0);
		}
		;

cascadeopts_l	: cascadeoptsl optcommanl cascadeopts_l
		| cascadeoptsl optnl
		;

cascadeoptsl	: STEP		{
			CALLOC(table, 1, sizeof(*table));
			SIMPLEQ_INSERT_TAIL(&target->cascade, table, tables);
			DPRINTF("next cascade step (flags <- %02X) enqueued",
			    table->flags);
			table->flags = ptable->flags;
		} stepopts	{
			ptable = table;
			table = SIMPLEQ_FIRST(&target->cascade);
		}
		| tableoptsl
		;

stepopts	: '{' optnl tableopts_l '}'
		| tableoptsl
		;

sockopts	: '{' optnl sockopts_l '}'
		| '{' optnl '}'
		| /* empty */
		;

sockopts_l	: sockoptsl optcommanl sockopts_l
		| sockoptsl optnl
		;

sockoptsl	: ACTION actionopt	{
			DPRINTF("action: %d", sock->action);
		}
		| BACKLOG NUMBER	{
			if ($2 <= 0 || $2 > CONF_BACKLOG_MAX) {
				yyerror("backlog out of bounds");
				YYERROR;
			}
			sock->backlog = $2;
			DPRINTF("backlog: %d", sock->backlog);
		}
		| DATAMAX NUMBER	{
			if ($2 <= 0 || $2 > CONF_DATAMAX_MAX) {
				yyerror("datamax out of bounds");
				YYERROR;
			}
			sock->datamax = $2;
			DPRINTF("datamax: %zd", sock->datamax);
		}
		| GROUP NUMBER		{
			struct group	*grp;

			if ((grp = getgrgid($2)) == NULL) {
				yyerror("group id not found");
				YYERROR;
			}
			sock->group = $2;
			DPRINTF("group: %d", sock->group);
		}
		| GROUP STRING		{
			struct group	*grp;

			if ((grp = getgrnam($2)) == NULL) {
				free($2);
				yyerror("group name not found");
				YYERROR;
			}
			sock->group = grp->gr_gid;
			DPRINTF("group: %s -> %d", $2, sock->group);
			free($2);
		}
		| ID STRING		{
			struct socket	*s;

			SIMPLEQ_FOREACH(s, &target->datasocks, sockets)
				if (!strncmp(s->id, $2, sizeof(s->id))) {
					free($2);
					yyerror("socket id defined twice "
					    "for same target");
					YYERROR;
				}
			if (strlcpy(sock->id, $2,
			    sizeof(sock->id)) >= sizeof(sock->id)) {
				free($2);
				yyerror("socket id too long");
				YYERROR;
			}
			free($2);
			DPRINTF("id: [%s]", sock->id);
		}
		| MODE NUMBER		{
			if ($2 < 0 || $2 > 0777) {
				yyerror("socket mode out of bounds");
				YYERROR;
			}
			sock->mode = $2;
			DPRINTF("mode: %04o", sock->mode);
		}
		| NO BACKLOG			{
			sock->backlog = CONF_NO_BACKLOG;
			DPRINTF("no backlog");
		}
		| NO DATAMAX		{
			sock->datamax = CONF_NO_DATAMAX;
			DPRINTF("no datamax");
		}
		| NO TIMEOUT		{
			sock->timeout = CONF_NO_TIMEOUT;
			DPRINTF("no timeout");
		}
		| OWNER NUMBER		{
			struct passwd	*pwd;

			if ((pwd = getpwuid($2)) == NULL) {
				yyerror("user id not found");
				YYERROR;
			}
			sock->owner = $2;
			DPRINTF("owner: %d", sock->owner);
		}
		| OWNER STRING		{
			struct passwd	*pwd;

			if ((pwd = getpwnam($2)) == NULL) {
				free($2);
				yyerror("user name not found");
				YYERROR;
			}
			sock->owner = pwd->pw_uid;
			DPRINTF("owner: %s -> %d", $2, sock->owner);
			free($2);
		}
		| TIMEOUT NUMBER	{
			if ($2 <= 0 || $2 > CONF_TIMEOUT_MAX) {
				yyerror("timeout out of bounds");
				YYERROR;
			}
			sock->timeout = $2;
			DPRINTF("timeout: %lld", sock->timeout);
		}
		;

actionopt	: ADD		{
			sock->action = ACTION_ADD;
		}
		| DELETE	{
			sock->action = ACTION_DELETE;
		}
		| DROP		{
			sock->action = ACTION_DROP;
		}
		;

exclude		: EXCLUDE '{' optnl excludeopts_l '}'
		| EXCLUDE excludeoptsl
		;

excludeopts_l	: excludeoptsl optcommanl excludeopts_l
		| excludeoptsl optnl
		;

excludeoptsl	: LOCALHOSTS		{
			if (load_exclude_cranges(HOSTS_FILE) == -1)
				YYERROR;
		}
		| NET STRING		{
			struct crange	*r;

			if ((r = parse_crange($2)) == NULL) {
				free($2);
				yyerror("invalid exclude net");
				YYERROR;
			}
			free($2);
			if (crange_inq(curr_exclcrangeq, r)) {
				DPRINTF("range [%s] already enqueued", r->str);
				free(r);
			} else {
				SIMPLEQ_INSERT_TAIL(curr_exclcrangeq, r,
				    cranges);
				DPRINTF("enqueued range [%s]", r->str);
			}
		}
		| NETFILE STRING	{
			if (load_exclude_cranges($2) == -1) {
				free($2);
				YYERROR;
			}
			free($2);
		}
		| KEYTERM STRING	{
			struct ptr	*k;

			MALLOC(k, sizeof(*k));
			STRDUP(k->p, $2);
			free($2);
			if (keyterm_inq(curr_exclkeytermq, k)) {
				DPRINTF("keyterm '%s' already enqueued", k->p);
				free(k->p);
				free(k);
			} else
				SIMPLEQ_INSERT_TAIL(curr_exclkeytermq, k,
				    ptrs);
		}
		| KEYTERMFILE STRING	{
			if (load_exclude_keyterms($2) == -1) {
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

tableopts_l	: tableoptsl optcommanl tableopts_l
		| tableoptsl optnl
		;

tableoptsl	: DROP TIME		{
			if ($2 <= 0 || $2 > CONF_DROP_MAX) {
				yyerror("drop time out of bounds");
				YYERROR;
			}
			table->drop.tv_sec = $2;
			DPRINTF("drop time: %lld", table->drop.tv_sec);
		}
		| EXPIRE TIME		{
			if ($2 <= 0 || $2 >= TIMESPEC_INFINITE.tv_sec) {
				yyerror("expire time out of bounds");
				YYERROR;
			}
			table->expire.tv_sec = $2;
			DPRINTF("expire time: %lld", table->expire.tv_sec);
		}
		| HITS NUMBER		{
			if ($2 <= 0 || $2 > UINT_MAX) {
				yyerror("hit count out of bounds");
				YYERROR;
			}
			table->hits = $2;
			DPRINTF("max. hit count: %u", table->hits);
		}
		| keep			{
			table->flags &= ~flags;
			DPRINTF("keep (%02X) -> flags: %02X", flags,
			    table->flags);
			flags = 0;
		}
		| kill			{
			table->flags |= flags;
			DPRINTF("kill (%02X) -> flags: %02X", flags,
			    table->flags);
			flags = 0;
		}
		| NO DROP		{
			table->drop = CONF_NO_DROP;
			DPRINTF("no drop");
		}
		| TABLE STRING		{
			if (strlcpy(table->name, $2,
			    sizeof(table->name)) >= sizeof(table->name)) {
				free($2);
				yyerror("table name too long");
				YYERROR;
			}
			free($2);
			DPRINTF("table name: '%s'", table->name);
		}
		;

keep		: KEEP '{' optnl kkopts_l '}'
		| KEEP kkoptsl
		;

kill		: KILL '{' optnl kkopts_l '}'
		| KILL kkoptsl
		;

kkopts_l	: kkoptsl optcommanl kkopts_l
		| kkoptsl optnl
		;

kkoptsl		: NODES		{
			flags |= FLAG_TABLE_KILL_NODES;
		}
		| STATES	{
			flags |= FLAG_TABLE_KILL_STATES;
		}
		;

optnl		: '\n' optnl
		| /* empty */
		;

optcommanl	: ',' optnl
		| optnl
		;

nl		: '\n' optnl
		;

%%

void
yyerror(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fprintf(stderr, " at line %d column %d\n", lineno + 1, colno + 1);
	yyerrflag = 1;
	errors++;
}

static const struct keyword {
	const char	*name;
	int		 token;
} keywords[] = {
	{ "action",	ACTION},
	{ "add",	ADD},
	{ "backlog",	BACKLOG},
	{ "cascade",	CASCADE },
	{ "datamax",	DATAMAX },
	{ "delete",	DELETE },
	{ "drop",	DROP },
	{ "exclude",	EXCLUDE },
	{ "expire",	EXPIRE },
	{ "group",	GROUP },
	{ "hits",	HITS },
	{ "id",		ID },
	{ "keep",	KEEP },
	{ "keyterm",	KEYTERM },
	{ "keytermfile", KEYTERMFILE },
	{ "kill",	KILL },
	{ "localhosts",	LOCALHOSTS },
	{ "log",	LOG },
	{ "mode",	MODE },
	{ "net",	NET },
	{ "netfile",	NETFILE },
	{ "no",		NO },
	{ "nodes",	NODES },
	{ "owner",	OWNER },
	{ "persist",	PERSIST },
	{ "skip",	SKIP },
	{ "socket",	SOCKET },
	{ "states",	STATES },
	{ "step",	STEP },
	{ "table",	TABLE },
	{ "target",	TARGET },
	{ "timeout",	TIMEOUT }
};

static int
crange_inq(struct crangeq *q, struct crange *r)
{
	struct crange	*r2;

	SIMPLEQ_FOREACH(r2, q, cranges)
		if (cranges_eq(r, r2))
			return (1);

	return (0);
}

static int
keyterm_inq(struct ptrq *q, struct ptr *k)
{
	struct ptr	*k2;

	SIMPLEQ_FOREACH(k2, q, ptrs)
		if (!strcmp(k->p, k2->p))
			return (1);

	return (0);
}

static int
load_exclude_keyterms(const char *file)
{
	char		 cpath[PATH_MAX], *line;
	FILE		*fp;
	size_t		 len;
	ssize_t		 n;
	int		 cnt;
	struct ptr	*k;

	YY_CANONICAL_PATH_SET(cpath, file, "keyterms file",, return (-1));

	if ((fp = fopen(cpath, "r")) == NULL) {
		yyerror("failed opening exclude keyterms file");
		return (-1);
	}

	line = NULL;
	len = 0;
	cnt = 0;

	while ((n = getline(&line, &len, fp)) != -1) {
		if (n == 1)
			continue;

		CALLOC(k, 1, sizeof(*k));
		if ((k->p = strndup(line, n - 1)) == NULL)
			FATAL("strndup(%s, %ld)", line, n - 1);
		if (keyterm_inq(curr_exclkeytermq, k)) {
			DPRINTF("keyterm '%s' already enqueued", k->p);
			free(k->p);
			free(k);
			continue;
		}

		SIMPLEQ_INSERT_TAIL(curr_exclkeytermq, k, ptrs);
		DPRINTF("enqueued keyterm '%s'", k->p);
		cnt++;
	}
	free(line);

	if (ferror(fp))
		log_warn("exclude keyterms file error");
	if (fclose(fp) == EOF)
		log_warn("exclude keyterms file close");

	return (cnt);
}

static int
load_exclude_cranges(const char *file)
{
	char		 cpath[PATH_MAX], *line;
	FILE		*fp;
	struct crange	*r;
	size_t		 len;
	ssize_t		 n;
	int		 cnt;

	YY_CANONICAL_PATH_SET(cpath, file, "networks file",, return (-1));

	if ((fp = fopen(cpath, "r")) == NULL) {
		yyerror("failed opening exclude addresses file");
		return (-1);
	}

	len = 0;
	line = NULL;
	cnt = 0;

	while ((n = getline(&line, &len, fp)) != -1) {
		if (n == 1 || *line == '#')
			continue;

		if ((r = parse_crange(replace(line, " \t\n", '\0'))) == NULL) {
			yyerror("invalid net '%s' in '%s'", line, file);
			cnt = -1;
			break;
		}
		if (crange_inq(curr_exclcrangeq, r)) {
			DPRINTF("range [%s] already enqueued", r->str);
			free(r);
		} else {
			SIMPLEQ_INSERT_TAIL(curr_exclcrangeq, r, cranges);
			DPRINTF("enqueued range [%s]", r->str);
			cnt++;
		}
	}
	free(line);

	if (ferror(fp))
		log_warn("exclude addresses file error");
	if (fclose(fp) == EOF)
		log_warn("exclude addresses file close");

	return (cnt);
}

int
yylex(void)
{
	char		 buf[BUFSIZ], *ebuf, *p, *ic;
	long long	 n;
	int		 c, quotes = 0, escape = 0, qpos = -1, nonkw = 0;

	p = buf;
	ebuf = buf + sizeof(buf);

repeat:
	/* skip whitespace first */
	for (c = getc(yyfp); c == ' ' || c == '\t'; c = getc(yyfp))
		colno++;

	/* check for special one-character constructions */
	switch (c) {
		case '\n':
			colno = 0;
			lineno++;
			/* FALLTHROUGH */
		case '{':
		case '}':
		case ',':
			return (c);

		case '#':
			/* skip comments; NUL is allowed; no continuation */
			while ((c = getc(yyfp)) != '\n')
				if (c == EOF)
					goto eof;
			colno = 0;
			lineno++;
			return (c);

		case EOF:
			goto eof;
	}

	/* parsing next word */
	for (;; c = getc(yyfp), colno++) {
		switch (c) {
		case '\0':
			yyerror("unallowed character NUL");
			escape = 0;
			continue;
		case '\\':
			escape = !escape;
			if (escape)
				continue;
			break;
		case '\n':
			if (quotes)
				yyerror("unterminated quotes");
			if (escape) {
				nonkw = 1;
				escape = 0;
				colno = 0;
				lineno++;
				continue;
			}
			goto eow;
		case EOF:
			if (escape)
				yyerror("unterminated escape");
			if (quotes)
				yyerror("unterminated quotes");
			goto eow;
		case '{':
		case '}':
		case '#':
		case ' ':
		case ',':
		case '\t':
			if (!escape && !quotes)
				goto eow;
			break;
		case '"':
			if (!escape) {
				quotes = !quotes;
				if (quotes) {
					nonkw = 1;
					qpos = colno;
				}
				continue;
			}
		}
		*p++ = c;
		if (p == ebuf) {
			yyerror("line too long");
			p = buf;
		}
		escape = 0;
	}

eow:
	*p = 0;
	if (c != EOF)
		ungetc(c, yyfp);
	if (p == buf) {
		if (c == EOF)
			goto eof;
		if (qpos == -1)
			goto repeat;
		if (!quotes)
			yyerror("empty argument");
		return (0);
	}
	if (!nonkw)
		for (c = NUMROWS(keywords); c > 0;) {
			c -= 1;
			if (!strcmp(buf, keywords[c].name))
				return (keywords[c].token);
		}
	if (qpos == -1) {
		if (isdigit(*buf)) {
			n = strlen(buf);
			ic = buf;
			errno = 0;
			yylval.v.number = strtoll(ic, &ic,
			    *ic == '0' && isdigit(ic[n - 1]) ? 8 : 10);
			if (errno) {
				yyerror("invalid number");
				return (0);
			}
			if (*ic == '\0')
				return (NUMBER);

			n = yylval.v.number;
			yylval.v.time = 0;
			do {
				switch (*ic) {
				case 's':
					break;
				case 'm':
					n *= 60;
					break;
				case 'h':
					n *= 60 * 60;
					break;
				case 'd':
					n *= 24 * 60 * 60;
					break;
				case 'w':
					n *= 7 * 24 * 60 * 60;
					break;
				default:
					errno = EINVAL;
				}
				if (errno)
					break;
				yylval.v.time += n;
				if (*++ic == '\0')
					break;
				n = strtoll(ic, &ic, 10);
			} while (!errno);
			if (errno) {
				yyerror("invalid number/time");
				return (0);
			}
			return (TIME);
		}
		if (*buf == '-')
			yyerror("negativ value");
		return (0);
	}
	STRDUP(yylval.v.string, buf);

	return (STRING);

eof:
	return (0);
}
