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

#include <stdarg.h>

#if DEBUG
#define LOGFMT(f, x, ...)	\
	f(x" [%s:%d:<%s>]", ##__VA_ARGS__, __FILE__, __LINE__, __func__)
#define FATAL(x, ...)	LOGFMT(fatal, x, ##__VA_ARGS__)
#define FATALX(x, ...)	LOGFMT(fatalx, x, ##__VA_ARGS__)
#define DPRINTF(x, ...)	LOGFMT(log_debug, x, ##__VA_ARGS__)
#else
#define FATAL(x, ...)	fatal("%s: "x, __func__, ##__VA_ARGS__)
#define FATALX(x, ...)	fatalx("%s: "x, __func__, ##__VA_ARGS__)
#define DPRINTF(...)	do {} while(0)
#endif

void	log_init(const char *, int, int);
void	log_procinit(const char *);
void	log_setdebug(int);
int	log_getdebug(void);
void	log_setverbose(int);
int	log_getverbose(void);
void	log_warn(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_warnx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_info(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	log_debug(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
void	logit(int, const char *, ...)
	    __attribute__((__format__ (printf, 2, 3)));
void	vlog(int, const char *, va_list)
	    __attribute__((__format__ (printf, 2, 0)));
__dead void fatal(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
__dead void fatalx(const char *, ...)
	    __attribute__((__format__ (printf, 1, 2)));
