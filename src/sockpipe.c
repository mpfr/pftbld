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

#define HANDLE_IOERR(e)				\
	do {					\
		if (errno != EAGAIN)		\
			err(1, "%s failed", e);	\
		NANONAP;			\
	} while (0)

__dead void
sockpipe(const char *path, int verbose)
{
	int			 fd;
	struct sockaddr_un	 ssa_un;
	char			 buf[BUFSIZ];
	ssize_t			 nr, nw, n;
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

	do {
		while ((nr = read(STDIN_FILENO, buf, sizeof(buf))) == -1)
			HANDLE_IOERR("stdin read");
		nw = 0;
		while (nw < nr) {
			while ((n = send(fd, &buf[nw], nr - nw, 0)) == -1)
				HANDLE_IOERR("socket write");
			if (n == 0)
				break;
			nw += n;
		}
	} while (nr);

	if (nw < 1 || buf[--nw] != '\0')
		while (send(fd, "", 1, 0) == -1)
			HANDLE_IOERR("socket write");

	if (!verbose)
		exit(0);

	do {
		while ((nr = recv(fd, buf, sizeof(buf), 0)) == -1)
			HANDLE_IOERR("socket read");
		nw = 0;
		while (nw < nr) {
			while ((n = write(STDOUT_FILENO, &buf[nw],
			    nr - nw)) == -1)
				HANDLE_IOERR("stdout write");
			if (n == 0)
				break;
			nw += n;
		}
	} while (nr);

	exit(0);
}
