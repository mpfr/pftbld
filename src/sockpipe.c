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

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>

#include "pftbld.h"

static ssize_t	 do_pipe(int, int, char *, const char *, const char *);

static ssize_t
do_pipe(int from, int to, char *buf, const char *errfrom, const char *errto)
{
	ssize_t	 nr, nw, n;

	do {
		while ((nr = read(from, buf, sizeof(buf))) == -1) {
			if (errno != EAGAIN)
				err(1, "%s", errfrom);

			NANONAP;
		}
		nw = 0;
		while (nw < nr) {
			while ((n = write(to, &buf[nw], nr - nw)) == -1) {
				if (errno != EAGAIN)
					err(1, "%s", errto);

				NANONAP;
			}
			if (n == 0)
				break;
			nw += n;
		}
	} while (nr);

	return (nw);
}

__dead void
sockpipe(const char *path, int verbose)
{
	int			 fd;
	struct sockaddr_un	 ssa_un;
	char			 buf[BUFSIZ];
	ssize_t			 nw;
	char			 cp[PATH_MAX];

	switch (check_path(path, cp, sizeof(cp))) {
	case PATH_OK:
		break;
	case PATH_EMPTY:
		errx(1, "empty path");
	case PATH_RELATIVE:
		errx(1, "path cannot be relative");
	case PATH_INVALID:
		errx(1, "invalid path");
	case PATH_DIRECTORY:
		errx(1, "path cannot be a directory");
	case PATH_FILENAME:
		errx(1, "invalid socket name");
	default:
		errx(1, "internal error");
	}

	memset(&ssa_un, 0, sizeof(ssa_un));
	ssa_un.sun_family = AF_UNIX;
	if (strlcpy(ssa_un.sun_path, cp,
	    sizeof(ssa_un.sun_path)) >= sizeof(ssa_un.sun_path))
		errx(1, "path too long");

	if (pledge("stdio unix unveil", NULL) == -1)
		err(1, "pledge failed");

	if (unveil(path, "r") == -1 || unveil(NULL, NULL) == -1)
		err(1, "unveil failed");

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
		err(1, "socket failed");

	if (connect(fd, (struct sockaddr *)&ssa_un, sizeof(ssa_un)) == -1)
		err(1, "connect failed");

	nw = do_pipe(STDIN_FILENO, fd, buf,
	    "stdin read failed", "socket write failed");

	if (nw < 1 || buf[--nw] != '\0')
		while (write(fd, "", 1) == -1) {
			if (errno != EAGAIN)
				err(1, "socket write failed");

			NANONAP;
		}

	if (!verbose)
		exit(0);

	(void)do_pipe(fd, STDOUT_FILENO, buf,
	    "socket read failed", "stdout write failed");

	exit(0);
}
