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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "pftbld.h"

int
load(struct target *tgt)
{
	const char	*file = tgt->persist, *errstr;
	FILE		*fp;
	char		*line, *arg;
	int		 cnt;
	struct client	*clt;
	size_t		 len;
	ssize_t		 llen;
	struct pfcmdq	 cmdq;
	struct clientq	 dcq;

	if (*file == '\0')
		return (-1);

	if ((fp = fopen(file, "r")) == NULL) {
		log_debug("opening persist file %s of target [%s] failed",
		    file, tgt->name);
		return (-1);
	}

	line = NULL;
	len = 0;
	cnt = 0;

	SIMPLEQ_INIT(&cmdq);
	TAILQ_INIT(&dcq);

	while ((llen = getline(&line, &len, fp)) != -1) {
		if (llen == 0 || *line == ';' || *line == '#')
			continue;

		CALLOC(clt, 1, sizeof(*clt));

		arg = replace(line, " \n", '\0');
		if (parse_addr(&clt->addr, arg) == -1) {
			log_warnx("ignored %s line %d: address '%s' invalid",
			    file, cnt + 1, arg);
			free(clt);
			continue;
		}

		if ((arg = shift(arg, line, --llen)) == NULL) {
			clt->hits = 1;
			GET_TIME(&clt->ts);
			goto end;
		}

		clt->hits = strtonum(arg, 0, UINT_MAX, &errstr);
		if (errstr != NULL) {
			log_warnx("ignored %s line %d: count '%s' %s", file,
			    cnt + 1, arg, errstr);
			free(clt);
			continue;
		}

		if ((arg = shift(arg, line, llen)) != NULL)
			clt->ts.tv_sec = strtonum(arg, 0, LLONG_MAX, &errstr);
		if (arg == NULL || errstr != NULL) {
			log_warnx("ignored %s line %d: timestamp '%s' %s",
			    file, cnt + 1, arg, errstr);
			free(clt);
			continue;
		}

end:
		clt->tgt = tgt;
		if (bind_table(clt, &cmdq)) {
			sort_client_desc(clt);
			cnt++;
			DPRINTF("client-%d (%s, hits:%d, ts:%lld, exp:%d, "
			    "to:%lld) created", cnt, line, clt->hits,
			    clt->ts.tv_sec, clt->exp, clt->to.tv_sec);
		} else {
			TAILQ_INSERT_TAIL(&dcq, clt, clients);
			DPRINTF("client (%s, hits:%d, ts:%lld, exp:%d, "
			    "to:%lld) discarded", line, clt->hits,
			    clt->ts.tv_sec, clt->exp, clt->to.tv_sec);
		}
	}
	free(line);

	apply_pfcmds(&cmdq);

	while ((clt = TAILQ_FIRST(&dcq)) != NULL) {
		TAILQ_REMOVE(&dcq, clt, clients);
		free(clt);
	}

	if (ferror(fp))
		log_warn("persist file error");
	if (fclose(fp) == EOF)
		log_warn("persist file close");

	return (cnt);
}

int
save(struct target *tgt)
{
	extern int		 privfd;
	extern struct clientq	 cltq;

	char		*file = tgt->persist;
	enum msgtype	 mt;
	int		 fd;
	FILE		*fp;
	struct client	*clt;
	int		 cnt;

	if (*file == '\0')
		return (-1);

	mt = MSG_HANDLE_PERSIST;
	ISEND(privfd, 2, &mt, sizeof(mt), file, sizeof(tgt->persist));
	/* wait for reply */
	RECV(privfd, &mt, sizeof(mt));
	if (mt != MSG_ACK)
		return (-1);

	while ((fd = recv_fd(&mt, sizeof(mt), privfd)) == -1)
		NANONAP;
	if (mt != MSG_ACK)
		FATALX("invalid message type (%d)", mt);
	if ((fp = fdopen(fd, "w")) == NULL) {
		close(fd);
		log_warn("failed opening persist file %s", file);
		mt = MSG_NAK;
		SEND(privfd, &mt, sizeof(mt));
		return (-1);
	}
	cnt = 0;
	TAILQ_FOREACH(clt, &cltq, clients)
		if (clt->tgt == tgt) {
			fprintf(fp, "%s %u %lld\n", clt->addr.str, clt->hits,
			    TIMESPEC_SEC_ROUND(&clt->ts));
			cnt++;
		}

	if (ferror(fp) || fclose(fp) == EOF)
		log_warn("persist file %s error", file);
	close(fd);

	mt = MSG_ACK;
	SEND(privfd, &mt, sizeof(mt));

	return (cnt);
}
