/*
 * Copyright (c) 2020 - 2024 Matthias Pressfreund
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

#include "log.h"
#include "pftbld.h"

static int	 cidr_to_norm_addr(char *, const char *, size_t);
static size_t	 norm_to_cidr_addr(char *, size_t, int, int);
static char	*append_age_unit(char *, time_t *, time_t, const char *);
static const char
		*canonicalize_path(const char *, char *, size_t);

void
drop_priv(void)
{
	struct passwd	*pw;

	if ((pw = getpwnam(PFTBLD_USER)) == NULL)
		FATAL("getpwnam");
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
	struct iovec	 iov[1];
	struct msghdr	 msg;
	char		 buf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr	*cmsg;
	ssize_t		 ns;

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

	if ((ns = sendmsg(cfd, &msg, 0)) == -1) {
		if (errno != EAGAIN && errno != EMFILE)
			FATAL("sendmsg");
		return (-1);
	}
	if (len - ns != 0)
		FATALX("invalid message length");

	return (0);
}

int
recv_fd(void *data, size_t maxlen, int cfd)
{
	struct iovec	 iov[1];
	struct msghdr	 msg;
	char		 buf[CMSG_SPACE(sizeof(int))];
	ssize_t		 nr;
	struct cmsghdr	*cmsg;

	iov[0].iov_base = data;
	iov[0].iov_len = maxlen;

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	if ((nr = recvmsg(cfd, &msg, 0)) == -1) {
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

#define BASIC_SEQ_IO(a, d, b, n, m)					\
	do {								\
		ssize_t	 _c;						\
		size_t	 _n = 0;					\
		while (n - _n > 0) {					\
			if ((_c = a(d, (void *)(&((char *)(b))[_n]),	\
			    n - _n, 0)) == -1)				\
				FATAL(m);				\
			if (_c == 0)					\
				FATALX("connection closed during "m);	\
			_n += _c;					\
		}							\
	} while (0)

void
send_data(int fd, void *data, size_t size)
{
	BASIC_SEQ_IO(send, fd, data, size, "send");
}

void
recv_data(int fd, void *data, size_t size)
{
	BASIC_SEQ_IO(recv, fd, data, size, "recv");
}

#define VALIST_IOV_IO(a, d, n, f, m)					\
	do {								\
		struct msghdr	 _msg;					\
		va_list		 _ap;					\
		int		 _i;					\
		struct iovec	 _iov[n];				\
		size_t		 _len = 0;				\
		ssize_t		 _c;					\
		memset(&_msg, 0, sizeof(_msg));				\
		va_start(_ap, n);					\
		for (_i = 0; _i < n; _i++) {				\
			_iov[_i].iov_base = va_arg(_ap, void *);	\
			_len += (_iov[_i].iov_len = va_arg(_ap, size_t)); \
		}							\
		va_end(_ap);						\
		_msg.msg_iov = _iov;					\
		_msg.msg_iovlen = n;					\
		if ((_c = a(d, &_msg, f)) == -1)			\
			FATAL(m);					\
		if (_c == 0)						\
			FATALX("connection closed during "m);		\
		if (_len - _c != 0)					\
			FATALX(m" buffer too small");			\
	} while (0)

void
send_valist(int fd, int n, ...)
{
	VALIST_IOV_IO(sendmsg, fd, n, 0, "sendmsg");
}

void
recv_valist(int fd, int n, ...)
{
	VALIST_IOV_IO(recvmsg, fd, n, MSG_WAITALL, "recvmsg");
}

static int
cidr_to_norm_addr(char *dst, const char *src, size_t dstsize)
{
	int		 bits, c, in6 = strchr(src, ':') != NULL;
	char		*d, *e;
	const char	*errstr, *b;
	size_t		 len;

	bits = (in6 ? sizeof(struct in6_addr) : sizeof(struct in_addr)) << 3;
	/* prepare CIDR prefix length to be removed, if present */
	e = (d = strchr(src, '/')) != NULL ? d : strchr(src, '\0');
	if ((len = e - src) >= dstsize)
		goto fail;

	if (d != NULL) {
		/* preserve CIDR prefix length to be returned later */
		bits = strtonum(++d, 0, bits, &errstr);
		if (errstr != NULL)
			goto fail;

	} else if (!in6) /* IPv4 only */
		/* reduce auto CIDR prefix length by trailing zero octets */
		while (--e >= src) {
			while (*e == '0') /* zeros may repeat */
				e--;
			if (*e != '.')
				break;
			bits -= 8;
		}

	memcpy(dst, src, len);
	dst[len] = '\0';

	if (in6)
		return (bits); /* leave IPv6 address as is */

	/* append missing zero octets */
	for (b = dst, c = 0;; b++, c++)
		if ((b = strchr(b, '.')) == NULL)
			break;
	for (c = 3 - c; c > 0; c--) {
		if (d == NULL) /* finalize auto IPv4 CIDR prefix length */
			bits -= 8;
		if (strlcat(dst, ".0", dstsize) >= dstsize)
			goto fail;
	}

	return (bits);

fail:
	*dst = '\0';
	return (-1);
}

static size_t
norm_to_cidr_addr(char *addr, size_t size, int range, int bits)
{
	char	*z = strchr(addr, '\0');
	size_t	 len;

	/* remove dispensable zero octets */
	while (range >= 8 && z - addr > 2 && !memcmp(z - 2, ".0", 2)) {
		range -= 8;
		z -= 2;
	}
	*z = '\0';

	/* append CIDR prefix length */
	len = z - addr;
	len += snprintf(z, size - len, "/%d", bits);

	return (len);
}

struct crange *
parse_crange(const char *str)
{
	char		 buf[INET6_ADDRSTRLEN];
	int		 bits, bytes, range;
	struct crange	*cr;
	unsigned char	*first, *last, b;

	if (str == NULL || *str == '\0' ||
	    (bits = cidr_to_norm_addr(buf, str, sizeof(buf))) == -1)
		return (NULL);

	CALLOC(cr, 1, sizeof(*cr));
	if (inet_pton(AF_INET, buf, &cr->first.ipv4) == 1) {
		if (inet_ntop(AF_INET, &cr->first.ipv4, cr->str,
		    sizeof(cr->str)) == NULL)
			FATAL("inet_ntop");
		cr->af = AF_INET;
		first = (unsigned char *)&cr->first.ipv4.s_addr;
		last = (unsigned char *)&cr->last.ipv4.s_addr;
		bytes = sizeof(struct in_addr);
	} else if (inet_pton(AF_INET6, buf, &cr->first.ipv6) == 1) {
		if (inet_ntop(AF_INET6, &cr->first.ipv6, cr->str,
		    sizeof(cr->str)) == NULL)
			FATAL("inet_ntop");
		cr->af = AF_INET6;
		first = (unsigned char *)&cr->first.ipv6.s6_addr;
		last = (unsigned char *)&cr->last.ipv6.s6_addr;
		bytes = sizeof(struct in6_addr);
	} else {
		free(cr);
		return (NULL);
	}
	range = bytes * 8 - bits;
	if (norm_to_cidr_addr(cr->str, sizeof(cr->str), range,
	    bits) >= sizeof(cr->str))
		FATALX("address truncated: %s", cr->str);
	cr->last = cr->first;
	b = (1 << range % 8) - 1;
	for (range /= 8; range; range--) {
		first[--bytes] = 0x00;
		last[bytes] = 0xff;
	}
	if (b) {
		first[--bytes] &= ~b;
		last[bytes] |= b;
	}
#if DEBUG
	if (cr->af == AF_INET)
		DPRINTF("\"%s\" bits:%d range:%08X...%08X", cr->str, bits,
		    be32toh(cr->first.ipv4.s_addr),
		    be32toh(cr->last.ipv4.s_addr));
	else
		DPRINTF("\"%s\" bits:%d range:%016llX%016llX...%016llX%016llX",
		    cr->str, bits,
		    be64toh(*(uint64_t *)cr->first.ipv6.s6_addr),
		    be64toh(*(uint64_t *)&cr->first.ipv6.s6_addr[8]),
		    be64toh(*(uint64_t *)cr->last.ipv6.s6_addr),
		    be64toh(*(uint64_t *)&cr->last.ipv6.s6_addr[8]));
#endif
	return (cr);
}

int
parse_addr(struct caddr *addr, const char *str)
{
	/* addr must be zeroed */
	if (inet_pton(AF_INET, str, &addr->pfaddr.pfra_ip4addr) == 1 &&
	    inet_ntop(AF_INET, &addr->pfaddr.pfra_ip4addr, addr->str,
	    sizeof(addr->str)) != NULL) {
		addr->pfaddr.pfra_af = AF_INET;
		addr->pfaddr.pfra_net = sizeof(struct in_addr) << 3;
	} else if (inet_pton(AF_INET6, str, &addr->pfaddr.pfra_ip6addr) == 1 &&
	    inet_ntop(AF_INET6, &addr->pfaddr.pfra_ip6addr, addr->str,
	    sizeof(addr->str)) != NULL) {
		addr->pfaddr.pfra_af = AF_INET6;
		addr->pfaddr.pfra_net = sizeof(struct in6_addr) << 3;
	} else {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

int
addr_inrange(struct crange *cr, struct caddr *addr)
{
	union inaddr	*iaddr;

	if (cr == NULL || addr == NULL)
		return (0);

	iaddr = (union inaddr *)&addr->pfaddr.pfra_u;

	return (addr->pfaddr.pfra_af == cr->af &&
	    addrvals_cmp(iaddr, &cr->first, cr->af) >= 0 &&
	    addrvals_cmp(iaddr, &cr->last, cr->af) <= 0);
}

int
addrs_cmp(struct caddr *a1, struct caddr *a2)
{
	uint8_t	 af1 = a1->pfaddr.pfra_af,
		 af2 = a2->pfaddr.pfra_af;

	if (af1 < af2)
		return (-1);

	if(af1 > af2)
		return (1);

	return (addrvals_cmp((union inaddr *)&a1->pfaddr.pfra_u,
	    (union inaddr *)&a2->pfaddr.pfra_u, af1));
}

int
addrvals_cmp(union inaddr *a1, union inaddr *a2, uint8_t af)
{
	if (af == AF_INET)
		return (memcmp(&a1->ipv4, &a2->ipv4, sizeof(struct in_addr)));

	if (af == AF_INET6)
		return (memcmp(&a1->ipv6, &a2->ipv6, sizeof(struct in6_addr)));

	return (a1 != a2);
}

int
cranges_eq(struct crange *r1, struct crange *r2)
{
	if (r1->af != r2->af)
		return (0);

	return (addrvals_cmp(&r1->first, &r2->first, r1->af) == 0 &&
	    addrvals_cmp(&r1->last, &r2->last, r1->af) == 0);
}

char *
shift(char *ptr, char *buf, size_t size)
{
	char	*next;

	if (ptr != NULL && buf != NULL &&
	    (next = strchr(ptr, '\0') + 1) < buf + size)
		return (next);

	return (NULL);
}

char *
replace(char *str, const char *old, const char new)
{
	int	 i;

	if (str == NULL)
		return (NULL);

	if (old == NULL)
		return (str);

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
		STRDUP(str, "infinite");
		return (str);
	}

	if ((age = TIMESPEC_SEC_ROUND(ts)) < 0) {
		STRDUP(str, "-");
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

int
prefill_socketopts(struct socket *s)
{
	char		*dir, *dpath;
	struct stat	 sb;

	STRDUP(dpath, s->path);
	if ((dir = dirname(dpath)) == NULL || stat(dir, &sb) == -1) {
		free(dpath);
		return (-1);
	}
	free(dpath);
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

	char	*apath;

	if (path == NULL || *path == '\0')
		return (PATH_EMPTY);

	if (*path == '/')
		STRDUP(apath, path);
	else if (basepath != NULL)
		ASPRINTF(&apath, "%s/%s", basepath, path);
	else
		return (PATH_RELATIVE);

	if (canonicalize_path(apath, cpath, cpathsize) == NULL) {
		free(apath);
		return (PATH_TRUNCATED);
	}
	free(apath);
	if (cpath[strlen(cpath) - 1] == '/')
		return (PATH_DIRECTORY);

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
rsend(int fd, const char *msg, size_t len)
{
	size_t	 nw;
	ssize_t	 n;

	for (nw = 0; nw < len; nw += n)
		if ((n = send(fd, msg + nw, len - nw, MSG_NOSIGNAL)) == -1 ||
		    n == 0) {
			if (errno == EPIPE)
				break;
			if (errno != EAGAIN)
				FATAL("send");
			NANONAP;
		}
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
		rsend(sfd->fd, msg, strlen(msg));
		free(msg);
	} else if (vdprintf(sfd->fd, fmt, args) == -1)
		FATAL("vdprintf");
	va_end(args);
}
