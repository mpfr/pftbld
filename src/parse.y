/*
 * Copyright (c) 2020 Matthias Pressfreund
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

static void yyerror(const char *, ...);
static int yylex(void);

static struct socket
		*create_socket(const char *);
static int	 load_exclude_keyterms(const char *);
static int	 crange_inq(struct crangeq *, struct crange *);
static int	 keyterm_inq(struct keytermq *, struct keyterm *);
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
static struct table	*table;
static uint8_t		 flags;

struct crangeq	*curr_exclcrangeq;
struct keytermq	*curr_exclkeytermq;

%}

%token	BACKLOG CASCADE DATAMAX DROP EXCLUDE EXPIRE GROUP HITS ID KEEP KEYTERMS
%token	KILL LOCALHOSTS LOG MODE NET NO NODES OWNER PERSIST SOCKET STATES STEP
%token	TABLE TARGET TIMEOUT
%token	<v.number>	NUMBER
%token	<v.string>	STRING
%token	<v.time>	TIME

%%

grammar		: /* empty */
		| grammar '\n'
		| grammar main '\n'
		;

main		: BACKLOG NUMBER		{
			if ($2 <= 0 || $2 >= INT_MAX) {
				yyerror("backlog out of bounds");
				YYERROR;
			}
			conf->backlog = $2;
			DPRINTF("global backlog: %d", conf->backlog);
		}
		| DATAMAX NUMBER		{
			if ($2 <= 0 || $2 >= LONG_MAX) {
				yyerror("datamax out of bounds");
				YYERROR;
			}
			conf->datamax = $2;
			DPRINTF("global datamax: %zu", conf->datamax);
		}
		| DROP TIME			{
			if ($2 <= 0 || $2 >= LLONG_MAX) {
				yyerror("drop time out of bounds");
				YYERROR;
			}
			conf->drop.tv_sec = $2;
			DPRINTF("global drop time: %lld", conf->drop.tv_sec);
		}
		| exclude
		| LOG STRING			{
			if (strlcpy(conf->log, $2,
			    sizeof(conf->log)) >= sizeof(conf->log)) {
				yyerror("log file path '%s' too long", $2);
				free($2);
				YYERROR;
			}
			free($2);
			conf->flags &= ~FLAG_GLOBAL_NOLOG;
			DPRINTF("log file is %s, flags: %02X", conf->log,
			    conf->flags);
		}
		| NO BACKLOG			{
			conf->backlog = INT_MAX;
			DPRINTF("no global backlog");
		}
		| NO DATAMAX			{
			conf->datamax = LONG_MAX;
			DPRINTF("no global datamax");
		}
		| NO DROP			{
			conf->drop = TIMESPEC_INFINITE;
			DPRINTF("no global drop");
		}
		| NO LOG			{
			conf->flags |= FLAG_GLOBAL_NOLOG;
			DPRINTF("no log, flags: %02X", conf->flags);
		}
		| NO TIMEOUT			{
			conf->timeout = LLONG_MAX;
			DPRINTF("no global timeout");
		}
		| TIMEOUT NUMBER		{
			if ($2 <= 0 || $2 >= LLONG_MAX) {
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
					yyerror("target [%s] defined twice",
					    $2);
					free($2);
					YYERROR;
				}
			CALLOC(target, 1, sizeof(*target));
			if (strlcpy(target->name, $2,
			    sizeof(target->name)) >= sizeof(target->name)) {
				yyerror("target name '%s' too long", $2);
				free($2);
				free(target);
				YYERROR;
			}
			free($2);
			SIMPLEQ_INIT(&target->datasocks);
			SIMPLEQ_INIT(&target->exclcranges);
			SIMPLEQ_INIT(&target->exclkeyterms);
			SIMPLEQ_INIT(&target->cascade);
			DPRINTF("current target is [%s]", target->name);
			SIMPLEQ_INSERT_TAIL(&conf->ctargets, target, targets);
			curr_exclcrangeq = &target->exclcranges;
			curr_exclkeytermq = &target->exclkeyterms;
		} '{' optnl targetopts_l '}'	{
			curr_exclcrangeq = &conf->exclcranges;
			curr_exclkeytermq = &conf->exclkeyterms;
		}
		;

targetopts_l	: targetopts_l targetoptsl nl
		| targetoptsl optnl
		;

targetoptsl	: CASCADE			{
			if (!SIMPLEQ_EMPTY(&target->cascade)) {
				yyerror("only one cascade per target "
				    "permitted");
				YYERROR;
			}
			CALLOC(table, 1, sizeof(*table));
			table->flags |= FLAG_TABLE_KILL_STATES;
			SIMPLEQ_INSERT_HEAD(&target->cascade, table, tables);
			DPRINTF("top cascade table enqueued");
		} '{' optnl cascadeopts_l '}'	{
			struct table	*t, *nt;
			int		 n;

			t = SIMPLEQ_FIRST(&target->cascade);
			if (*t->name == '\0') {
				yyerror("missing cascade head table");
				YYERROR;
			}
			n = 1;
			while ((nt = SIMPLEQ_NEXT(t, tables)) != NULL) {
				if (t->hits == 0) {
					yyerror("cascade step %d unreachable",
					    n);
					YYERROR;
				}
				if (nt->hits == 0)
					DPRINTF("cascade closed by step %d", n);
				else if (nt->hits <= t->hits) {
					yyerror("hits of cascade step %d must "
					    "be greater than %d", n, t->hits);
					YYERROR;
				}
				if (*nt->name == '\0') {
					strcpy(nt->name, t->name); /* len ok */
					DPRINTF("step %d inherited table name "
					    "<%s>", n, nt->name);
				}
				t = nt;
				n++;
			}
			if (t->hits > 0) {
				yyerror("open cascade after %d hits", t->hits);
				YYERROR;
			}
		}
		| DROP TIME			{
			if ($2 <= 0 || $2 >= LLONG_MAX) {
				yyerror("drop time out of bounds");
				YYERROR;
			}
			target->drop.tv_sec = $2;
			DPRINTF("drop time of target [%s]: %lld", target->name,
			    target->drop.tv_sec);
		}
		| exclude
		| NO DROP			{
			target->drop = TIMESPEC_INFINITE;
			DPRINTF("no drop for target [%s]", target->name);
		}
		| PERSIST STRING		{
			char		 path[PATH_MAX];
			enum pathres	 pres;

			pres = check_path($2, path, sizeof(path), NULL);
			switch (pres) {
			case PATH_OK:
				break;
			case PATH_EMPTY:
				yyerror("empty persist file path");
				free($2);
				YYERROR;
			case PATH_RELATIVE:
				yyerror("persist file path cannot be "
				    "relative");
				free($2);
				YYERROR;
			case PATH_INVALID:
				yyerror("invalid persist file path");
				free($2);
				YYERROR;
			case PATH_DIRECTORY:
				yyerror("persist file path cannot be a "
				    "directory");
				free($2);
				YYERROR;
			case PATH_FILENAME:
				yyerror("invalid persist file name");
				free($2);
				YYERROR;
			default:
				FATALX("invalid path check result (%d)", pres);
			}
			if (strlcpy(target->persist, path,
			    sizeof(target->persist)) >=
			    sizeof(target->persist)) {
				yyerror("persist file path too long");
				free($2);
				YYERROR;
			}
			free($2);
			DPRINTF("persist file is %s", target->persist);
		}
		| SOCKET STRING			{
			if ((sock = create_socket($2)) == NULL) {
				free($2);
				YYERROR;
			}
			free($2);
			if (prefill_socketopts(sock) == -1) {
				yyerror("prefill socket options failed for %s",
				    sock->path);
				free(sock);
				YYERROR;
			}
			DPRINTF("current data socket at %s", sock->path);
			SIMPLEQ_INSERT_TAIL(&target->datasocks, sock, sockets);
		} sockopts
		;

cascadeopts_l	: cascadeoptsl optcommanl cascadeopts_l
		| cascadeoptsl optnl
		;

cascadeoptsl	: STEP				{
			struct table	*last, *next;

			CALLOC(table, 1, sizeof(*table));
			last = SIMPLEQ_FIRST(&target->cascade);
			while ((next = SIMPLEQ_NEXT(last, tables)) != NULL)
				last = next;
			table->flags = last->flags;
			SIMPLEQ_INSERT_TAIL(&target->cascade, table, tables);
			DPRINTF("next cascade table (flags <- %02X) enqueued",
			    table->flags);
		} '{' optnl tableopts_l '}'	{
			table = SIMPLEQ_FIRST(&target->cascade);
		}
		| tableoptsl
		;

sockopts	: '{' optnl sockopts_l '}'
		| '{' optnl '}'
		| /* empty */
		;

sockopts_l	: sockoptsl optcommanl sockopts_l
		| sockoptsl optnl
		;

sockoptsl	: BACKLOG NUMBER	{
			if ($2 <= 0 || $2 >= INT_MAX) {
				yyerror("backlog out of bounds");
				YYERROR;
			}
			sock->backlog = $2;
			DPRINTF("backlog: %d", conf->backlog);
		}
		| DATAMAX NUMBER	{
			if ($2 <= 0 || $2 >= LONG_MAX) {
				yyerror("datamax out of bounds");
				YYERROR;
			}
			sock->datamax = $2;
			DPRINTF("datamax: %zu", sock->datamax);
		}
		| GROUP NUMBER		{
			struct group	*grp;

			if ((grp = getgrgid($2)) == NULL) {
				yyerror("group id (%d) not found", $2);
				YYERROR;
			}
			sock->group = $2;
			DPRINTF("socket %s group: %d", sock->path,
			    sock->group);
		}
		| GROUP STRING		{
			struct group	*grp;

			if ((grp = getgrnam($2)) == NULL) {
				yyerror("group '%s' not found", $2);
				free($2);
				YYERROR;
			}
			sock->group = grp->gr_gid;
			DPRINTF("group: %s -> %d", $2, sock->group);
			free($2);
		}
		| ID STRING		{
			if (strlcpy(sock->id, $2,
			    sizeof(sock->id)) >= sizeof(sock->id)) {
				yyerror("socket id '%s' too long", $2);
				free($2);
				YYERROR;
			}
			DPRINTF("id: [%s]", $2);
			free($2);
		}
		| MODE NUMBER		{
			if ($2 < 0 || $2 > 0777) {
				yyerror("socket mode out of bounds");
				YYERROR;
			}
			sock->mode = $2;
			DPRINTF("mode: %03o", sock->mode);
		}
		| NO BACKLOG			{
			sock->backlog = INT_MAX;
			DPRINTF("no backlog");
		}
		| NO DATAMAX		{
			sock->datamax = LONG_MAX;
			DPRINTF("no datamax");
		}
		| NO TIMEOUT		{
			sock->timeout = LLONG_MAX;
			DPRINTF("no timeout");
		}
		| OWNER NUMBER		{
			struct passwd	*pwd;

			if ((pwd = getpwuid($2)) == NULL) {
				yyerror("user id (%d) not found", $2);
				YYERROR;
			}
			sock->owner = $2;
			DPRINTF("owner: %d", sock->owner);
		}
		| OWNER STRING		{
			struct passwd	*pwd;

			if ((pwd = getpwnam($2)) == NULL) {
				yyerror("user '%s' not found", $2);
				free($2);
				YYERROR;
			}
			sock->owner = pwd->pw_uid;
			DPRINTF("owner: %s -> %d", $2, sock->owner);
			free($2);
		}
		| TIMEOUT NUMBER	{
			if ($2 <= 0 || $2 >= LLONG_MAX) {
				yyerror("timeout out of bounds");
				YYERROR;
			}
			sock->timeout = $2;
			DPRINTF("timeout: %lld", sock->timeout);
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
				yyerror("invalid exclude value");
				free($2);
				YYERROR;
			}
			if (!crange_inq(curr_exclcrangeq, r)) {
				SIMPLEQ_INSERT_TAIL(curr_exclcrangeq, r,
				    cranges);
				DPRINTF("enqueued range [%s]", $2);
			} else
				DPRINTF("range [%s] already enqueued", $2);
			free($2);
		}
		| KEYTERMS STRING	{
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
			if ($2 <= 0 || $2 >= LLONG_MAX) {
				yyerror("drop time out of bounds");
				YYERROR;
			}
			table->drop.tv_sec = $2;
			DPRINTF("drop time: %lld", table->drop.tv_sec);
		}
		| EXPIRE TIME		{
			if ($2 <= 0 || $2 >= LLONG_MAX) {
				yyerror("expire time out of bounds");
				YYERROR;
			}
			table->expire.tv_sec = $2;
			DPRINTF("expire time: %lld", table->expire.tv_sec);
		}
		| HITS NUMBER		{
			table->hits = $2;
			DPRINTF("max. hits count: %d", table->hits);
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
			table->drop = TIMESPEC_INFINITE;
			DPRINTF("no drop");
		}
		| TABLE STRING		{
			if (strlcpy(table->name, $2,
			    sizeof(table->name)) >= sizeof(table->name)) {
				yyerror("table name '%s' too long", $2);
				free($2);
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
	{ "backlog",	BACKLOG},
	{ "cascade",	CASCADE },
	{ "datamax",	DATAMAX },
	{ "drop",	DROP },
	{ "exclude",	EXCLUDE },
	{ "expire",	EXPIRE },
	{ "group",	GROUP },
	{ "hits",	HITS },
	{ "id",		ID },
	{ "keep",	KEEP },
	{ "keyterms",	KEYTERMS },
	{ "kill",	KILL },
	{ "localhosts",	LOCALHOSTS },
	{ "log",	LOG },
	{ "mode",	MODE },
	{ "net",	NET },
	{ "no",		NO },
	{ "nodes",	NODES },
	{ "owner",	OWNER },
	{ "persist",	PERSIST },
	{ "socket",	SOCKET },
	{ "states",	STATES },
	{ "step",	STEP },
	{ "table",	TABLE },
	{ "target",	TARGET },
	{ "timeout",	TIMEOUT }
};

static struct socket *
create_socket(const char *path)
{
	char		 cpath[PATH_MAX];
	enum pathres	 pres;
	struct socket	*s;

	pres = check_path(path, cpath, sizeof(cpath), NULL);
	switch (pres) {
	case PATH_OK:
		break;
	case PATH_EMPTY:
		yyerror("empty socket path");
		return (NULL);
	case PATH_RELATIVE:
		yyerror("socket path cannot be relative");
		return (NULL);
	case PATH_INVALID:
		yyerror("invalid socket path");
		return (NULL);
	case PATH_DIRECTORY:
		yyerror("socket path cannot be a directory");
		return (NULL);
	case PATH_FILENAME:
		yyerror("invalid socket file name");
		return (NULL);
	default:
		FATALX("invalid path check result (%d)", pres);
	}
	CALLOC(s, 1, sizeof(*s));
	if (strlcpy(s->path, cpath, sizeof(s->path)) >= sizeof(s->path)) {
		yyerror("socket path too long");
		free(s);
		return (NULL);
	}
	return (s);
}

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
keyterm_inq(struct keytermq *q, struct keyterm *k)
{
	struct keyterm	*k2;

	SIMPLEQ_FOREACH(k2, q, keyterms)
		if (!strcmp(k->str, k2->str))
			return (1);

	return (0);
}

static int
load_exclude_keyterms(const char *file)
{
	FILE		*fp;
	char		*line;
	size_t		 len;
	ssize_t		 n;
	int		 cnt;
	struct keyterm	*k;

	if ((fp = fopen(file, "r")) == NULL) {
		yyerror("failed opening exclude keyterms file '%s'", file);
		return (-1);
	}

	line = NULL;
	len = 0;
	cnt = 0;

	while ((n = getline(&line, &len, fp)) != -1) {
		if (n == 0)
			continue;

		CALLOC(k, 1, sizeof(*k));
		if ((k->str = strndup(line, n - 1)) == NULL)
			FATAL("strndup(%s, %ld)", line, n - 1);
		if (keyterm_inq(curr_exclkeytermq, k)) {
			DPRINTF("keyterm '%s' already enqueued", k->str);
			free(k->str);
			free(k);
			continue;
		}

		SIMPLEQ_INSERT_TAIL(curr_exclkeytermq, k, keyterms);
		DPRINTF("enqueued keyterm '%s'", k->str);
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
	FILE		*fp;
	char		*line;
	struct crange	*r;
	size_t		 len;
	ssize_t		 n;
	int		 cnt;

	if ((fp = fopen(file, "r")) == NULL) {
		yyerror("failed opening exclude addresses file '%s'", file);
		return (-1);
	}

	len = 0;
	line = NULL;
	cnt = 0;

	while ((n = getline(&line, &len, fp)) != -1) {
		if (n == 0 || *line == '#')
			continue;

		line = replace(line, " \t\n", '\0');

		if ((r = parse_crange(line)) == NULL) {
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
	char		 buf[BUFSIZ], *ebuf, *p, *lbuf, *ic;
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
			errno = 0;
			lbuf = buf + strlen(buf);
			yylval.v.number = strtoll(buf, &ic, 0);
			if (errno)
				yyerror("invalid number");
			else if (ic == lbuf)
				return (NUMBER);
			n = yylval.v.number;
			yylval.v.time = 0;
			while (1) {
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
				yylval.v.time += n;
				if (errno || ++ic >= lbuf)
					break;
				if ((n = strtoll(ic, &ic, 0)) == 0) {
					errno = EINVAL;
					break;
				}
			}
			if (errno)
				yyerror("invalid number/time");
			return (TIME);
		}
		if (*buf == '-')
			yyerror("negativ value");
		return (0);
	}
	if ((yylval.v.string = strdup(buf)) == NULL)
		FATAL("strdup(%s)", buf);

	return (STRING);

eof:
	return (0);
}
