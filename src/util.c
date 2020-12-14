/*
 * Copyright (c) 2020 Matthias Pressfreund
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
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

#include <errno.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <net/if.h>

#include "log.h"
#include "pftbld.h"

static char	*append_age_unit(char *, time_t *, time_t, const char *);
static const char
		*canonicalize_path(const char *, char *, size_t);

void
drop_priv(void)
{
	struct passwd	*pw;

	if ((pw = getpwnam(PFTBLD_USER)) == NULL)
		FATAL("setpwnam");
	if (chroot(pw->pw_dir) == -1)
		FATAL("chroot");
	if (chdir("/") == -1)
		FATAL("chdir");
	if (setgroups(1, &pw->pw_gid) == -1)
		FATAL("setgroups");
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		FATAL("setresgid");
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		FATAL("setresuid");
}

int
send_fd(int fd, void *data, size_t len, int cfd)
{
	size_t		 ns;
	struct iovec	 iov[1];
	struct msghdr	 msg;
	struct cmsghdr	*cmsg;
	char		 buf[CMSG_SPACE(sizeof(int))];

	iov[0].iov_base = data;
	iov[0].iov_len = len;

	memset(buf, 0, sizeof(buf));
	memset(&msg, 0, sizeof(msg));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	*(int *)CMSG_DATA(cmsg) = fd;

	if ((ns = sendmsg(cfd, &msg, 0)) == -1UL) {
		if (errno != EAGAIN && errno != EMFILE)
			FATAL("sendmsg");
		return (-1);
	}
	if (ns != len)
		FATALX("invalid message length");

	return (0);
}

int
recv_fd(void *data, size_t maxlen, int cfd)
{
	size_t		 nr;
	struct iovec	 iov[1];
	struct msghdr	 msg;
	struct cmsghdr	*cmsg;
	char		 buf[CMSG_SPACE(sizeof(int))];

	iov[0].iov_base = data;
	iov[0].iov_len = maxlen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if ((nr = recvmsg(cfd, &msg, 0)) == -1UL) {
		if (errno != EAGAIN && errno != EMSGSIZE)
			FATAL("recvmsg");
		return (-1);
	}
	if (nr == 0)
		FATALX("connection closed");

	if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
		FATALX("control message truncated");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg))
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
		    cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS)
			return (*(int *)CMSG_DATA(cmsg));

	FATALX("no file descriptor");
}

struct crange *
parse_crange(const char *str)
{
	struct crange	*r;
	int		 bits, j, k, b;
	unsigned char	*first, *last;

	if (str == NULL || *str == '\0')
		return (NULL);

	CALLOC(r, 1, sizeof(*r));

	if ((bits = inet_net_pton(AF_INET, str, &r->first.ipv4,
	    sizeof(struct in_addr))) != -1) {
		if (inet_net_ntop(AF_INET, &r->first.ipv4, bits, r->str,
		    sizeof(r->str)) == NULL)
			FATAL("inet_net_ntop");
		r->type = IPv4;
		r->last = r->first;
		first = (unsigned char *)&r->first.ipv4.s_addr;
		last = (unsigned char *)&r->last.ipv4.s_addr;
		j = 32 - bits;
		k = 3;
	} else if ((bits = inet_net_pton(AF_INET6, str, &r->first.ipv6,
	    sizeof(struct in6_addr))) != -1) {
		if (inet_net_ntop(AF_INET6, &r->first.ipv6, bits, r->str,
		    sizeof(r->str)) == NULL)
			FATAL("inet_net_ntop");
		r->type = IPv6;
		r->last = r->first;
		first = (unsigned char *)&r->first.ipv6.s6_addr;
		last = (unsigned char *)&r->last.ipv6.s6_addr;
		j = 128 - bits;
		k = 15;
	} else {
		free(r);
		return (NULL);
	}
	for (b = 0; j > 0; j -= 1) {
		first[k] &= ~(1 << b);
		last[k] |= 1 << b;
		if (++b > 7) {
			b = 0;
			k -= 1;
		}
	}
#if DEBUG
	if (r->type == IPv4)
		DPRINTF("\"%s\" bits:%d range:%08X...%08X", r->str, bits,
		    be32toh(r->first.ipv4.s_addr),
		    be32toh(r->last.ipv4.s_addr));
	else
		DPRINTF("\"%s\" bits:%d range:%016llX%016llX...%016llX%016llX",
		    r->str, bits,
		    be64toh(*(uint64_t *)r->first.ipv6.s6_addr),
		    be64toh(*(uint64_t *)&r->first.ipv6.s6_addr[8]),
		    be64toh(*(uint64_t *)r->last.ipv6.s6_addr),
		    be64toh(*(uint64_t *)&r->last.ipv6.s6_addr[8]));
#endif
	return (r);
}

int
parse_addr(struct caddr *addr, const char *str)
{
	memset(addr, 0, sizeof(*addr));
	if (inet_pton(AF_INET, str, &addr->value.ipv4) == 1)
		addr->type = IPv4;
	else if (inet_pton(AF_INET6, str, &addr->value.ipv6) == 1)
		addr->type = IPv6;
	else {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
addr_inrange(struct crange *cr, struct caddr *addr)
{
	if (cr == NULL || addr == NULL)
		return (0);

	return (addr->type == cr->type &&
	    addrvals_cmp(&addr->value, &cr->first, cr->type) >= 0 &&
	    addrvals_cmp(&addr->value, &cr->last, cr->type) <= 0);
}

int
addrs_cmp(struct caddr *a1, struct caddr *a2)
{
	if (a1->type != a2->type)
		return (1);

	return (addrvals_cmp(&a1->value, &a2->value, a1->type));
}

int
addrvals_cmp(union addrvalue *a1, union addrvalue *a2, enum addrtype t)
{
	if (t == IPv4)
		return (memcmp(&a1->ipv4, &a2->ipv4, sizeof(struct in_addr)));

	if (t == IPv6)
		return (memcmp(&a1->ipv6, &a2->ipv6, sizeof(struct in6_addr)));

	return (a1 != a2);
}

int
cranges_eq(struct crange *r1, struct crange *r2)
{
	if (r1->type != r2->type)
		return (0);

	return (addrvals_cmp(&r1->first, &r2->first, r1->type) == 0 &&
	    addrvals_cmp(&r1->last, &r2->last, r1->type) == 0);
}

char *
shift(char *ptr, char *buf, size_t size)
{
	char	*next;

	if (ptr == NULL || buf == NULL)
		return (NULL);

	next = ptr + strlen(ptr) + 1;

	if (next < buf + size)
		return (next);

	return (NULL);
}

char *
replace(char *str, const char *old, const char new)
{
	int	 i;

	for (i = 0; str[i] != '\0'; i++)
		if (strchr(old, str[i]) != NULL)
			str[i] = new;

	return (str);
}

static char *
append_age_unit(char *str, time_t *age, time_t unit, const char *fmt)
{
	char	*buf, *next;

	if (*age < unit && unit > 1) /* age assumed non-negative here */
		return (str);

	if (asprintf(&buf, fmt, *age / unit) == -1 ||
	    asprintf(&next, "%s%s", str, buf) == -1)
		FATAL("asprintf");

	free(buf);
	free(str);

	*age %= unit;

	return (next);
}

char *
hrage(struct timespec *ts)
{
	char	*str;
	time_t	 unit, age;

	if (timespec_isinfinite(ts)) {
		if ((str = strdup("infinite")) == NULL)
			FATAL("strdup");
		return (str);
	}

	if ((age = TIMESPEC_SEC_ROUND(ts)) < 0) {
		if ((str = strdup("-")) == NULL)
			FATAL("strdup");
		age = -age;
	} else
		CALLOC(str, 1, 1);

	if (age == 0) {
		unit = 1;
		goto last;
	}
	unit = 7 * 24 * 60 * 60;

	str = append_age_unit(str, &age, unit, "%lldw");
	if (age == 0)
		return (str);

	unit /= 7;
	str = append_age_unit(str, &age, unit, "%lldd");
	if (age == 0)
		return (str);

	unit /= 24;
	str = append_age_unit(str, &age, unit, "%lldh");
	if (age == 0)
		return (str);

	unit /= 60;
	str = append_age_unit(str, &age, unit, "%lldm");
	if (age == 0)
		return (str);

	unit /= 60;
last:
	return (append_age_unit(str, &age, unit, "%llds"));
}

char *
addrstr(char *str, size_t size, struct caddr *addr)
{
	char	 buf[INET6_ADDRSTRLEN];

	if (addr->type != IPv4 && addr->type != IPv6) {
		errno = EINVAL;
		return (NULL);
	}
	if ((addr->type == IPv4 && inet_ntop(AF_INET, &addr->value.ipv4, buf,
	    sizeof(buf)) == NULL) ||
	    (addr->type == IPv6 && inet_ntop(AF_INET6, &addr->value.ipv6, buf,
	    sizeof(buf)) == NULL))
		return (NULL);

	if (strlcpy(str, buf, size) >= size) {
		log_debug("address truncated (%s -> %s)", buf, str);
		errno = EINVAL;
		return (NULL);
	}
	return (str);
}

int
prefill_socketopts(struct socket *s)
{
	char		*dir, *dpath;
	struct stat	 sb;

	if ((dpath = strdup(s->path)) == NULL)
		FATAL("strdup");
	if ((dir = dirname(dpath)) == NULL) {
		free(dpath);
		return (-1);
	}
	free(dpath);
	if (stat(dir, &sb) == -1)
		return (-1);

	s->owner = sb.st_uid;
	DPRINTF("socket %s default owner id: %d", s->path, s->owner);
	s->group = sb.st_gid;
	DPRINTF("socket %s default group id: %d", s->path, s->group);
	s->mode = DEFAULT_SOCKMOD;
	DPRINTF("socket %s default mode: %04o", s->path, s->mode);

	return (0);
}

static const char *
canonicalize_path(const char *input, char *path, size_t len)
{
	const char	*i;
	char		*p, *start, *end;

	/* assuming input starts with '/' and is nul-terminated */
	i = input;
	p = path;

	if (*input != '/' || len < 3)
		return (NULL);

	start = p;
	end = p + (len - 1);

	while (*i != '\0') {
		/* Detect truncation */
		if (p >= end)
			return (NULL);

		/* 1. check for special path elements */
		if (i[0] == '/') {
			if (i[1] == '/') {
				/* a) skip repeating '//' slashes */
				while (i[1] == '/')
					i++;
				continue;
			} else if (i[1] == '.' && i[2] == '.' &&
			    (i[3] == '/' || i[3] == '\0')) {
				/* b) revert '..' to previous directory */
				i += 3;
				while (p > start && *p != '/')
					p--;
				*p = '\0';
				continue;
			} else if (i[1] == '.' &&
			    (i[2] == '/' || i[2] == '\0')) {
				/* c) skip unnecessary '.' current dir */
				i += 2;
				continue;
			}
		}

		/* 2. copy any other characters */
		*p++ = *i;
		i++;
	}
	if (p == start)
		*p++ = '/';
	*p++ = '\0';

	return (path);
}

enum pathres
check_path(const char *path, char *cpath, size_t cpathsize)
{
	extern char	*basepath;

	char	*apath, *dpath, *file;

	if (*path == '\0')
		return (PATH_EMPTY);

	if (*path == '/') {
		if ((apath = strdup(path)) == NULL)
			FATAL("strdup");
	} else if (basepath != NULL) {
		if (asprintf(&apath, "%s/%s", basepath, path) == -1)
			FATAL("asprintf");
	} else
		return (PATH_RELATIVE);

	if (canonicalize_path(apath, cpath, cpathsize) == NULL) {
		free(apath);
		return (PATH_INVALID);
	}
	free(apath);
	if (cpath[strlen(cpath) - 1] == '/')
		return (PATH_DIRECTORY);

	if ((dpath = strdup(cpath)) == NULL)
		FATAL("strdup");
	if ((file = basename(dpath)) == NULL || *file == '/' || *file == '.') {
		free(dpath);
		return (PATH_FILENAME);
	}
	free(dpath);
	return (PATH_OK);
}

struct statfd *
create_statfd(int fd)
{
	struct statfd	*sfd;

	MALLOC(sfd, sizeof(*sfd));
	if (fstat(fd, &sfd->sb) == -1)
		FATAL("fstat");
	sfd->fd = fd;
	return (sfd);
}

void
msg_send(struct statfd *sfd, const char *fmt, ...)
{
	va_list	 args;
	char	*msg;

	va_start(args, fmt);
	if (S_ISSOCK(sfd->sb.st_mode)) {
		if (vasprintf(&msg, fmt, args) == -1)
			FATAL("vasprintf");
		while (send(sfd->fd, msg, strlen(msg), MSG_NOSIGNAL) == -1) {
			if (errno != EAGAIN)
				break; /* ignore errors */
			NANONAP;
		}
		free(msg);
	} else if (vdprintf(sfd->fd, fmt, args) == -1)
		FATAL("vdprintf");
	va_end(args);
}
