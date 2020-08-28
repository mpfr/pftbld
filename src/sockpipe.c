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

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>

#include "pftbld.h"

__dead void
sockpipe(const char *path, int verbose)
{
	int			 fd;
	struct sockaddr_un	 ssa_un;
	char			 buf[BUFSIZ];
	ssize_t			 nr, nw, n;

	if (path == NULL || *path == '\0' || strlen(path) >= PATH_MAX)
		errx(1, "invalid path");

	memset(&ssa_un, 0, sizeof(ssa_un));
	ssa_un.sun_family = AF_UNIX;
	if (strlcpy(ssa_un.sun_path, path,
	    sizeof(ssa_un.sun_path)) >= sizeof(ssa_un.sun_path))
		errx(1, "path too long");

	if (pledge("stdio unix unveil", NULL) == -1)
		err(1, "pledge failed");

	if (unveil(path, "r") == -1 || unveil(NULL, NULL) == -1)
		err(1, "unveil failed");

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
		err(1, "socket failed");

	if (connect(fd, (struct sockaddr *)&ssa_un, sizeof(ssa_un)) == -1)
		err(1, "connect (%s) failed", path);

	nw = 0;
	do {
		while ((nr = read(STDIN_FILENO, buf, sizeof(buf))) == -1) {
			if (errno != EAGAIN)
				err(1, "stdin read failed");
			NANONAP;
		}
		n = 0;
		while (n < nr) {
			while ((nw = write(fd, &buf[n], nr - n)) == -1) {
				if (errno != EAGAIN)
					err(1, "socket write failed");
				NANONAP;
			}
			n += nw;
		}
	} while (nr);

	if (nw < 1 || buf[nw - 1] != '\0')
		while (write(fd, "", 1) == -1) {
			if (errno != EAGAIN)
				err(1, "socket write failed");
			NANONAP;
		}

	if (!verbose)
		exit(0);

	do {
		while ((nr = read(fd, buf, sizeof(buf))) == -1) {
			if (errno != EAGAIN)
				err(1, "socket read failed");
			NANONAP;
		}
		n = 0;
		while (n < nr) {
			while ((nw = write(STDOUT_FILENO, &buf[n],
			    nr - n)) == -1) {
				if (errno != EAGAIN)
					err(1, "stdout write failed");
				NANONAP;
			}
			n += nw;
		}
	} while (nr);

	exit(0);
}
