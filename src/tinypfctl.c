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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <sys/ioctl.h>

#include "log.h"
#include "pftbld.h"

#define PF_DEVICE	"/dev/pf"

static struct pfioc_table
		*pf_table_prepare(const char *);
static int	 pf_add_table(int, const char *);
static struct pfioc_table
		*pf_addresses_prepare(const char *, struct pfr_addr *, size_t);
#if DEBUG
static void	 log_mod_table(const char *, struct pfr_addr *, int,
		    const char *);
#endif
static int	 pf_add_addresses(int, const char *, struct pfr_addr *,
		    size_t);
static int	 pf_delete_addresses(int, const char *, struct pfr_addr *,
		    size_t);
static int	 pf_kill_states(int, struct pfr_addr *);
static int	 pf_kill_nodes(int, struct pfr_addr *);

static struct pfioc_table *
pf_table_prepare(const char *name)
{
	struct pfr_table	*tbl;
	struct pfioc_table	*io = NULL;

	if ((tbl = calloc(1, sizeof(*tbl))) == NULL)
		goto fail;

	if (strlcpy(tbl->pfrt_name, name,
	    sizeof(tbl->pfrt_name)) >= sizeof(tbl->pfrt_name)) {
		errno = ENAMETOOLONG;
		goto fail;
	}
	if ((io = calloc(1, sizeof(*io))) == NULL)
		goto fail;

	io->pfrio_buffer = tbl;
	io->pfrio_esize = sizeof(*tbl);
	io->pfrio_size = 1;
	return (io);

fail:
	free(tbl);
	free(io);
	return (NULL);
}

static int
pf_add_table(int pffd, const char *name)
{
	struct pfioc_table	*io;
	struct pfr_table	*tbl = NULL;
	int			 nadd;

	if ((io = pf_table_prepare(name)) == NULL)
		goto fail;

	tbl = io->pfrio_buffer;
	tbl->pfrt_flags |= PFR_TFLAG_PERSIST;

	if (ioctl(pffd, DIOCRADDTABLES, io) == -1)
		goto fail;

	nadd = io->pfrio_nadd;

	free(tbl);
	free(io);
#if DEBUG
	if (nadd > 0)
		DPRINTF("table <%s> added", name);
#endif
	return (nadd);

fail:
	free(tbl);
	free(io);
	return (-1);
}

static struct pfioc_table *
pf_addresses_prepare(const char *tname, struct pfr_addr *addrs, size_t n)
{
	struct pfioc_table	*io;
	struct pfr_table	*tbl;

	if ((io = pf_table_prepare(tname)) == NULL)
		return (NULL);

	tbl = io->pfrio_buffer;
	io->pfrio_table = *tbl;
	free(tbl);

	io->pfrio_buffer = addrs;
	io->pfrio_esize = sizeof(*addrs);
	io->pfrio_size = n;
	return (io);
}

#if DEBUG
static void
log_mod_table(const char *tname, struct pfr_addr *addr, int n, const char *mod)
{
	char	*add;

	if (--n) {
		if (asprintf(&add, "(+%d more address%s) ", n,
		    n != 1 ? "es" : "") == -1)
			FATAL("asprintf");
	} else
		CALLOC(add, 1, 1);
	if (addr->pfra_af == AF_INET)
		DPRINTF("%08X %s%s table <%s>",
		    be32toh(addr->pfra_ip4addr.s_addr), add, mod, tname);
	else
		DPRINTF("%016llX%016llX %s%s table <%s>",
		    be64toh(*(uint64_t *)addr->pfra_ip6addr.s6_addr),
		    be64toh(*(uint64_t *)&addr->pfra_ip6addr.s6_addr[8]),
		    add, mod, tname);
	free(add);
}
#endif

static int
pf_add_addresses(int pffd, const char *tname, struct pfr_addr *addrs, size_t n)
{
	struct pfioc_table	*io = NULL;
	int			 nadd;

	if (pf_add_table(pffd, tname) == -1)
		goto fail;

	if ((io = pf_addresses_prepare(tname, addrs, n)) == NULL)
		goto fail;

	if (ioctl(pffd, DIOCRADDADDRS, io) == -1)
		goto fail;

	nadd = io->pfrio_nadd;

	free(io);
#if DEBUG
	if (nadd > 0)
		log_mod_table(tname, addrs, nadd, "added to");
#endif
	return (nadd);

fail:
	free(io);
	return (-1);
}

static int
pf_delete_addresses(int pffd, const char *tname, struct pfr_addr *addrs,
    size_t n)
{
	struct pfioc_table	*io = NULL;
	int			 ndel;

	if (pf_add_table(pffd, tname) == -1)
		goto fail;

	if ((io = pf_addresses_prepare(tname, addrs, n)) == NULL)
		goto fail;

	if (ioctl(pffd, DIOCRDELADDRS, io) == -1)
		goto fail;

	ndel = io->pfrio_ndel;

	free(io);
#if DEBUG
	if (ndel > 0)
		log_mod_table(tname, addrs, ndel, "deleted from");
#endif
	return (ndel);

fail:
	free(io);
	return (-1);
}

static int
pf_kill_states(int pffd, struct pfr_addr *addr)
{
	struct pfioc_state_kill	 psk;

	memset(&psk, 0, sizeof(psk));
	memset(&psk.psk_src.addr.v.a.mask, 0xff,
	    sizeof(psk.psk_src.addr.v.a.mask));

	psk.psk_af = addr->pfra_af;
	switch (psk.psk_af) {
	case AF_INET:
		psk.psk_src.addr.v.a.addr.v4 = addr->pfra_ip4addr;
		break;
	case AF_INET6:
		psk.psk_src.addr.v.a.addr.v6 = addr->pfra_ip6addr;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (ioctl(pffd, DIOCKILLSTATES, &psk) == -1)
		return (-1);

	return (psk.psk_killed);
}

static int
pf_kill_nodes(int pffd, struct pfr_addr *addr)
{
	struct pfioc_src_node_kill	 psnk;

	memset(&psnk, 0, sizeof(psnk));
	memset(&psnk.psnk_src.addr.v.a.mask, 0xff,
	    sizeof(psnk.psnk_src.addr.v.a.mask));

	psnk.psnk_af = addr->pfra_af;
	switch (psnk.psnk_af) {
	case AF_INET:
		psnk.psnk_src.addr.v.a.addr.v4 = addr->pfra_ip4addr;
		break;
	case AF_INET6:
		psnk.psnk_src.addr.v.a.addr.v6 = addr->pfra_ip6addr;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (ioctl(pffd, DIOCKILLSRCNODES, &psnk) == -1)
		return (-1);

	return (psnk.psnk_killed);
}

__dead void
tinypfctl(int argc, char *argv[])
{
	int		 debug, verbose, ctrlfd, pffd;
	char		*cmd, *table, *buf;
	size_t		 buflen, acnt, c;
	struct pfr_addr	*pfaddr;
	struct caddr	 caddr;
	struct pfresult	 pfres;

	ETOI(debug, ENV_DEBUG);
	ETOI(verbose, ENV_VERBOSE);
	log_init(argv[1], debug, verbose);
	setproctitle("%s", __func__);

	ETOI(ctrlfd, ENV_CTRLFD);

	buf = argv[2];
	buflen = strlen(buf) + 1;

	cmd = replace(buf, "\n", '\0');
	if ((table = shift(cmd, buf, buflen)) == NULL)
		FATALX("missing table");
	DPRINTF("received cmd:'%s', table:'%s'", cmd, table);
	/* wait for client addresses */
	READ(ctrlfd, &acnt, sizeof(acnt));
	CALLOC(pfaddr, acnt, sizeof(*pfaddr));
	for (c = 0; c < acnt; c++) {
		READ(ctrlfd, &caddr, sizeof(caddr));
		switch (caddr.type) {
		case IPv4:
			pfaddr[c].pfra_af = AF_INET;
			pfaddr[c].pfra_ip4addr = caddr.value.ipv4;
			pfaddr[c].pfra_net = 32;
			break;
		case IPv6:
			pfaddr[c].pfra_af = AF_INET6;
			pfaddr[c].pfra_ip6addr = caddr.value.ipv6;
			pfaddr[c].pfra_net = 128;
			break;
		default:
			FATALX("invalid address");
		}
	}

	memset(&pfres, 0, sizeof(pfres));

	if ((pffd = open(PF_DEVICE, O_RDWR)) == -1)
		FATAL("open");

	if (!strcmp("add", cmd)) {
		if ((pfres.nadd = pf_add_addresses(pffd, table, pfaddr,
		    acnt)) == -1)
			FATAL("pf_add_addresses");
		if ((cmd = shift(table, buf, buflen)) == NULL)
			goto end;

		if (acnt > 1)
			FATALX("kill option on address array");
		if (*cmd == 's') {
			DPRINTF("received option:'%s'", cmd);
			if ((pfres.nkill = pf_kill_states(pffd, pfaddr)) == -1)
				FATAL("pf_kill_states");
			if ((cmd = shift(cmd, buf, buflen)) == NULL)
				goto end;
		}
		if (*cmd != 'n')
			FATALX("invalid kill option '%s'", cmd);
		DPRINTF("received option:'%s'", cmd);
		if ((pfres.snkill = pf_kill_nodes(pffd, pfaddr)) == -1)
			FATAL("pf_kill_nodes");
	} else if (!strcmp("delete", cmd)) {
		if ((pfres.ndel = pf_delete_addresses(pffd, table, pfaddr,
		    acnt)) == -1)
			FATAL("pf_delete_addresses");
		cmd = table;
	} else
		FATALX("invalid command '%s'", cmd);

	if ((cmd = shift(cmd, buf, buflen)) != NULL)
		FATALX("invalid command extension '%s'", cmd);

end:
	close(pffd);
	free(pfaddr);
	/* send reply */
	WRITE(ctrlfd, &pfres, sizeof(pfres));
	exit(0);
}

void
fork_tinypfctl(struct pfresult *pfres, char *cmd, struct caddrq *caq,
    size_t acnt)
{
	extern const struct procfunc	 process[];
	extern char			*__progname;

	int		 ctrlfd[2], pid;
	char		*argv[4];
	struct caddr	*ca;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, ctrlfd) == -1)
		FATAL("socketpair");

	if ((pid = fork()) == -1)
		FATAL("fork");

	if (pid == 0) { /* child */
		close(ctrlfd[0]);
		ITOE(ENV_CTRLFD, ctrlfd[1]);

		argv[0] = process[PROC_TINYPFCTL].name;
		argv[1] = __progname;
		argv[2] = cmd;
		argv[3] = NULL;

		execvp(__progname, argv);
		FATAL("execvp");
	}
	/* parent */
	close(ctrlfd[1]);

	WRITE(ctrlfd[0], &acnt, sizeof(acnt));
	while ((ca = SIMPLEQ_FIRST(caq)) != NULL) {
		WRITE(ctrlfd[0], ca, sizeof(*ca));
		SIMPLEQ_REMOVE_HEAD(caq, caddrs);
		free(ca);
	}
	/* wait for reply */
	READ(ctrlfd[0], pfres, sizeof(*pfres));
	DPRINTF("received pfresult (nadd:%d, ndel:%d, nkill:%d, snkill:%d)",
	    pfres->nadd, pfres->ndel, pfres->nkill, pfres->snkill);

	close(ctrlfd[0]);
}
