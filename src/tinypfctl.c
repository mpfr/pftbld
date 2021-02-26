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
	struct pfioc_table	*io;

	if ((tbl = calloc(1, sizeof(*tbl))) == NULL)
		return (NULL);

	if (strlcpy(tbl->pfrt_name, name,
	    sizeof(tbl->pfrt_name)) >= sizeof(tbl->pfrt_name)) {
		free(tbl);
		errno = ENAMETOOLONG;
		return (NULL);
	}
	if ((io = calloc(1, sizeof(*io))) == NULL) {
		free(tbl);
		free(io);
		return (NULL);
	}
	io->pfrio_buffer = tbl;
	io->pfrio_esize = sizeof(*tbl);
	io->pfrio_size = 1;
	return (io);
}

static int
pf_add_table(int pffd, const char *name)
{
	struct pfioc_table	*io;
	struct pfr_table	*tbl;
	int			 nadd;

	if ((io = pf_table_prepare(name)) == NULL)
		return (-1);

	tbl = io->pfrio_buffer;
	tbl->pfrt_flags |= PFR_TFLAG_PERSIST;

	if (ioctl(pffd, DIOCRADDTABLES, io) == -1) {
		free(tbl);
		free(io);
		return (-1);
	}
	free(tbl);
	nadd = io->pfrio_nadd;
	free(io);
#if DEBUG
	if (nadd > 0)
		DPRINTF("table <%s> added", name);
#endif
	return (nadd);
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

	if (--n)
		ASPRINTF(&add, "(+%d more address%s) ", n, n != 1 ? "es" : "");
	else
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
	struct pfioc_table	*io;
	int			 nadd;

	if (pf_add_table(pffd, tname) == -1 ||
	    (io = pf_addresses_prepare(tname, addrs, n)) == NULL)
		return (-1);

	if (ioctl(pffd, DIOCRADDADDRS, io) == -1) {
		free(io);
		return (-1);
	}
	nadd = io->pfrio_nadd;
	free(io);
#if DEBUG
	if (nadd > 0)
		log_mod_table(tname, addrs, nadd, "added to");
#endif
	return (nadd);
}

static int
pf_delete_addresses(int pffd, const char *tname, struct pfr_addr *addrs,
    size_t n)
{
	struct pfioc_table	*io;
	int			 ndel;

	if (pf_add_table(pffd, tname) == -1 ||
	    (io = pf_addresses_prepare(tname, addrs, n)) == NULL)
		return (-1);

	if (ioctl(pffd, DIOCRDELADDRS, io) == -1) {
		free(io);
		return (-1);
	}
	ndel = io->pfrio_ndel;
	free(io);
#if DEBUG
	if (ndel > 0)
		log_mod_table(tname, addrs, ndel, "deleted from");
#endif
	return (ndel);
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
	struct pfcmd	 cmd;
	size_t		 c;
	struct pfr_addr	*pfaddr;
	struct caddr	 addr;
	struct pfresult	 pfres;

	ETOI(debug, ENV_DEBUG);
	ETOI(verbose, ENV_VERBOSE);
	log_init(argv[1], debug, verbose);
	setproctitle("%s", __func__);

	ETOI(ctrlfd, ENV_CTRLFD);

	STOI(cmd.id, argv[2]);
	cmd.tblname = argv[3];
	STOI(cmd.flags, argv[4]);
	STOLL(cmd.addrcnt, argv[5]);

	DPRINTF("received cmdid:%d, tblname:'%s', flags:%u, addrcnt:%zu",
	    cmd.id, cmd.tblname, cmd.flags, cmd.addrcnt);
	/* wait for client addresses */
	CALLOC(pfaddr, cmd.addrcnt, sizeof(*pfaddr));
	for (c = 0; c < cmd.addrcnt; c++) {
		RECV(ctrlfd, &addr, sizeof(addr));
		switch (addr.type) {
		case ADDR_IPV4:
			pfaddr[c].pfra_af = AF_INET;
			pfaddr[c].pfra_ip4addr = addr.value.ipv4;
			pfaddr[c].pfra_net = 32;
			break;
		case ADDR_IPV6:
			pfaddr[c].pfra_af = AF_INET6;
			pfaddr[c].pfra_ip6addr = addr.value.ipv6;
			pfaddr[c].pfra_net = 128;
			break;
		default:
			FATALX("invalid address type (%d)", addr.type);
		}
	}

	memset(&pfres, 0, sizeof(pfres));

	if ((pffd = open(PF_DEVICE, O_RDWR)) == -1)
		FATAL("open");

	switch (cmd.id) {
	case PFCMD_ADD:
		if ((pfres.nadd = pf_add_addresses(pffd, cmd.tblname, pfaddr,
		    cmd.addrcnt)) == -1)
			FATAL("pf_add_addresses");
		if (cmd.addrcnt > 1 && cmd.flags)
			FATALX("kill option on address array");
		if (cmd.flags & FLAG_TABLE_KILL_STATES) {
			DPRINTF("received kill states flag");
			if ((pfres.nkill = pf_kill_states(pffd, pfaddr)) == -1)
				FATAL("pf_kill_states");
		}
		if (cmd.flags & FLAG_TABLE_KILL_NODES) {
			DPRINTF("received kill nodes flag");
			if ((pfres.snkill = pf_kill_nodes(pffd, pfaddr)) == -1)
				FATAL("pf_kill_nodes");
		}
		break;
	case PFCMD_DELETE:
		if ((pfres.ndel = pf_delete_addresses(pffd, cmd.tblname,
		    pfaddr, cmd.addrcnt)) == -1)
			FATAL("pf_delete_addresses");
		break;
	default:
		FATALX("invalid command id (%d)", cmd.id);
	}

	close(pffd);
	free(pfaddr);
	/* send reply */
	SEND(ctrlfd, &pfres, sizeof(pfres));
	exit(0);
}

void
fork_tinypfctl(struct pfresult *pfres, struct pfcmd *cmd)
{
	extern const struct procfunc	 process[];
	extern char			*__progname;

	int		 ctrlfd[2], pid;
	char		*argv[7];
	struct caddr	*ca;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, ctrlfd) == -1)
		FATAL("socketpair");

	if ((pid = fork()) == -1)
		FATAL("fork");

	if (pid == 0) { /* child */
		close(ctrlfd[0]);
		ITOE(ENV_CTRLFD, ctrlfd[1]);

		argv[0] = process[PROC_TINYPFCTL].name;
		argv[1] = __progname;
		ITOS(argv[2], cmd->id);
		argv[3] = cmd->tblname;
		ITOS(argv[4], cmd->flags);
		LLTOS(argv[5], (long long)cmd->addrcnt);
		argv[6] = NULL;

		execvp(__progname, argv);
		FATAL("execvp");
	}
	/* parent */
	close(ctrlfd[1]);

	while ((ca = SIMPLEQ_FIRST(&cmd->addrq)) != NULL) {
		SEND(ctrlfd[0], ca, sizeof(*ca));
		SIMPLEQ_REMOVE_HEAD(&cmd->addrq, caddrs);
		free(ca);
	}
	/* wait for reply */
	RECV(ctrlfd[0], pfres, sizeof(*pfres));
	free(cmd->tblname);
	DPRINTF("received pfresult (nadd:%d, ndel:%d, nkill:%d, snkill:%d)",
	    pfres->nadd, pfres->ndel, pfres->nkill, pfres->snkill);

	close(ctrlfd[0]);
}
