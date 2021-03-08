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

#include "pftbld.h"

#define ERR(m)	err(1, "%s failed", m)

__dead void
sockpipe(const char *path, int verbose)
{
	int			 fd;
	struct sockaddr_un	 ssa_un;
	char			 buf[BUFSIZ];
	ssize_t			 nr, nw, n;

	memset(&ssa_un, 0, sizeof(ssa_un));
	CANONICAL_PATH_SET_0(ssa_un.sun_path, path, "socket", warnx, exit(1),
	    errx(1, "internal error"));
	ssa_un.sun_family = AF_UNIX;

	if (pledge("stdio unix unveil", NULL) == -1)
		ERR("pledge");

	if (unveil(ssa_un.sun_path, "r") == -1 || unveil(NULL, NULL) == -1)
		ERR("unveil");

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		ERR("socket");

	if (connect(fd, (struct sockaddr *)&ssa_un, sizeof(ssa_un)) == -1)
		ERR("connect");

	do {
		if ((nr = read(STDIN_FILENO, buf, sizeof(buf))) == -1)
			ERR("stdin read");
		nw = 0;
		while (nw < nr) {
			if ((n = send(fd, &buf[nw], nr - nw, 0)) == -1)
				ERR("socket write");
			if (n == 0)
				break;
			nw += n;
		}
	} while (nr > 0);

	if ((nw < 1 || buf[--nw] != '\0') && send(fd, "", 1, 0) == -1)
		ERR("socket write");

	if (!verbose)
		exit(0);

	do {
		if ((nr = recv(fd, buf, sizeof(buf), 0)) == -1)
			ERR("socket read");
		nw = 0;
		while (nw < nr) {
			if ((n = write(STDOUT_FILENO, &buf[nw],
			    nr - nw)) == -1)
				ERR("stdout write");
			if (n == 0)
				break;
			nw += n;
		}
	} while (nr > 0);

	exit(0);
}
