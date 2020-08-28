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
$
```

Get the sources downloaded and extracted.

```
$ ftp -o - https://codeload.github.com/mpfr/pftbld/tar.gz/master | tar xzvf -
pftbld-master
pftbld-master/README.md
pftbld-master/docs
pftbld-master/docs/mandoc.css
pftbld-master/docs/pftblctl.8.html
pftbld-master/docs/pftbld.8.html
pftbld-master/docs/pftbld.conf.5.html
pftbld-master/pkg
pftbld-master/pkg/pftbld.conf
pftbld-master/pkg/pftbld.rc
pftbld-master/src
pftbld-master/src/Makefile
pftbld-master/src/config.c
pftbld-master/src/listener.c
pftbld-master/src/log.c
pftbld-master/src/log.h
pftbld-master/src/logger.c
pftbld-master/src/parse.y
pftbld-master/src/persist.c
pftbld-master/src/pftblctl.8
pftbld-master/src/pftblctl.sh
pftbld-master/src/pftbld.8
pftbld-master/src/pftbld.c
pftbld-master/src/pftbld.conf.5
pftbld-master/src/pftbld.h
pftbld-master/src/scheduler.c
pftbld-master/src/sockpipe.c
pftbld-master/src/tinypfctl.c
pftbld-master/src/util.c
$
```

Compile the sources and install the `pftbld` binary, the `pftblctl` tool and the manpages.

```
$ cd pftbld-master/src
$ doas make obj
making /home/mpfr/pftbld-master/src/obj
$ doas make
yacc  -o parse.c /home/mpfr/pftbld-master/src/parse.y
cc -O2 -pipe  -Wall -I/home/mpfr/pftbld-master/src -Wstrict-prototypes ...
.
.
.
cc   -o pftbld parse.o config.o listener.o log.o logger.o persist.o ...
$ doas make install
install -c -s  -o root -g bin  -m 555 pftbld /usr/local/sbin/pftbld
install -c -o root -g bin -m 555  /home/mpfr/pftbld-master/src/pftblctl.sh ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-master/src/pftblctl.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-master/src/pftbld.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-master/src/pftbld.conf.5 ...
$
```

Create the `_pftbld` user.

```
$ doas useradd -c "pftbld unprivileged user" -d /var/empty -g =uid -r 100..999 -s /sbin/nologin _pftbld
$
```

Install the service script.

```
$ doas install -c -o root -g bin -m 555 ../pkg/pftbld.rc /etc/rc.d/pftbld
$ doas rcctl enable pftbld
$
```

Create a [configuration file](https://mpfr.github.io/pftbld/pftbld.conf.5.html) at the default location`/etc/pftbld/pftbld.conf`, e.g. by copying and adapting the [example](pkg/pftbld.conf) to your needs. When you're done, make sure to get the result verified.

```
$ doas mkdir /etc/pftbld
$ doas install -c -m 644 ../pkg/pftbld.conf /etc/pftbld
$ doas vi /etc/pftbld/pftbld.conf
...
$ doas pftbld -n
configuration OK
$
```

Start the `pftbld` daemon.

```
$ doas rcctl start pftbld
pftbld(ok)
$
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
$
```
