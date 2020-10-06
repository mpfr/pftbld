# pftbld

`pftbld` is a lightweight [OpenBSD](https://www.openbsd.org) daemon written to automate [pf(4) table](http://man.openbsd.org/pf.conf#TABLES) content management and is typically used for maintaining dynamic firewall blacklists.

For further information, please have a look at the manpages of [pftbld(8)](https://mpfr.github.io/pftbld/pftbld.8.html), its configuration file [pftbld.conf(5)](https://mpfr.github.io/pftbld/pftbld.conf.5.html), and its control tool [pftblctl(8)](https://mpfr.github.io/pftbld/pftblctl.8.html).

## How to install

As there is no [package](https://www.openbsd.org/faq/faq15.html) available yet, `pftbld` needs to be built from source and installed manually. Luckily, this is easy and straightforward. Just follow the steps below.

Make sure your user has sufficient `doas` permissions. To start, `cd` into the user's home directory, here `/home/mpfr`.

```
$ cat /etc/doas.conf
permit nopass mpfr
$ cd
$ pwd
/home/mpfr
```

Get the sources downloaded and extracted.

```
$ rm -rf pftbld-main/
$ ftp -Vo - https://codeload.github.com/mpfr/pftbld/tar.gz/main | tar xzvf -
pftbld-main
pftbld-main/LICENSE
pftbld-main/README.md
pftbld-main/docs
pftbld-main/docs/mandoc.css
pftbld-main/docs/pftblctl.8.html
pftbld-main/docs/pftbld.8.html
pftbld-main/docs/pftbld.conf.5.html
pftbld-main/pkg
pftbld-main/pkg/pftbld.conf
pftbld-main/pkg/pftbld.rc
pftbld-main/src
pftbld-main/src/Makefile
pftbld-main/src/config.c
pftbld-main/src/listener.c
pftbld-main/src/log.c
pftbld-main/src/log.h
pftbld-main/src/logger.c
pftbld-main/src/parse.y
pftbld-main/src/persist.c
pftbld-main/src/pftblctl.8
pftbld-main/src/pftblctl.sh
pftbld-main/src/pftbld.8
pftbld-main/src/pftbld.c
pftbld-main/src/pftbld.conf.5
pftbld-main/src/pftbld.h
pftbld-main/src/scheduler.c
pftbld-main/src/sockpipe.c
pftbld-main/src/tinypfctl.c
pftbld-main/src/util.c
```

Compile the sources and install the `pftbld` binary, the `pftblctl` tool and the manpages.

```
$ cd pftbld-main/src
$ doas make obj
making /home/mpfr/pftbld-main/src/obj
$ doas make
yacc  -o parse.c /home/mpfr/pftbld-main/src/parse.y
cc -O2 -pipe  -Wall -I/home/mpfr/pftbld-main/src -Wstrict-prototypes ...
.
.
.
cc   -o pftbld parse.o config.o listener.o log.o logger.o persist.o ...
$ doas make install
install -c -s  -o root -g bin  -m 555 pftbld /usr/local/sbin/pftbld
install -c -o root -g bin -m 555  /home/mpfr/pftbld-main/src/pftblctl.sh ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-main/src/pftblctl.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-main/src/pftbld.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-main/src/pftbld.conf.5 ...
```

Create the `_pftbld` user.

```
$ doas useradd -c "pftbld unprivileged user" -d /var/empty -g =uid -r 100..999 -s /sbin/nologin _pftbld
```

Install the service script.

```
$ doas install -c -o root -g bin -m 555 ../pkg/pftbld.rc /etc/rc.d/pftbld
$ doas rcctl enable pftbld
```

Create a [configuration file](https://mpfr.github.io/pftbld/pftbld.conf.5.html) at the default location`/etc/pftbld/pftbld.conf`, e.g. by copying and adapting the [example](pkg/pftbld.conf) to your needs. When you're done, make sure to get the result verified.

```
$ doas mkdir /etc/pftbld
$ doas install -c -m 644 ../pkg/pftbld.conf /etc/pftbld
$ doas vi /etc/pftbld/pftbld.conf
...
$ doas pftbld -n
configuration OK
```

Start the `pftbld` daemon.

```
$ doas rcctl start pftbld
pftbld(ok)
```

## How to uninstall

```
$ doas rcctl stop pftbld
pftbld(ok)
$ doas rcctl disable pftbld
$ doas rm /etc/rc.d/pftbld
$ doas rm /usr/local/man/man{5,8}/pftbl*
$ doas rm /usr/local/sbin/pftbl*
$ doas rmuser _pftbld
...
$ doas rm -rf /etc/pftbld
```
