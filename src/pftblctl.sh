#!/bin/ksh
#
# Copyright (c) 2020 - 2024 Matthias Pressfreund
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

usage()
{
	echo "usage: ${0##*/} [-q] [-s <socket>] <command/address>" \
	    '[<argument> ...]' >&2
	exit 1
}

err()
{
	echo "${0##*/}: $1" >&2
	exit 1
}

PFTBLD='/usr/local/sbin/pftbld'
[[ -x ${PFTBLD} ]] || err 'pftbld binary missing or not executable'

QUIET=0
SOCKET='/var/run/pftbld.sock'
while getopts qs: arg; do
	case ${arg} in
	q)	QUIET=$((QUIET+1));;
	s)	SOCKET=$OPTARG;;
	*)	usage;;
	esac
done
[[ -S ${SOCKET} ]] || err "no socket found at '${SOCKET}'"
shift $((OPTIND-1))

for a in "$@"; do
	[[ -n "${cmd}" ]] && cmd="${cmd}\n${a}" || cmd="${a}"
done

[[ -n "${cmd}" ]] || usage

((QUIET < 2)) && VERBOSE='v'
((QUIET == 1)) && exec 1>/dev/null

echo -n "${cmd}" | ${PFTBLD} -${VERBOSE}p ${SOCKET}
