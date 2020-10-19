# pftbld

`pftbld` is a lightweight [OpenBSD](https://www.openbsd.org) daemon written to automate [pf(4) table](http://man.openbsd.org/pf.conf#TABLES) content management and is typically used for maintaining dynamic firewall blacklists.

## How to install

As there is no [package](https://www.openbsd.org/faq/faq15.html) available, `pftbld` needs to be built from source and installed manually. Luckily, this is easy and straightforward. Just follow the steps below.

Make sure you're running `OpenBSD 6.7-stable`. Otherwise, one of the following branches might be more appropriate:
* [current](https://github.com/mpfr/pftbld)
* [6.8-stable](https://github.com/mpfr/pftbld/tree/6.8-stable)

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
$ rm -rf pftbld-6.7-stable/
$ ftp -Vo - https://codeload.github.com/mpfr/pftbld/tar.gz/6.7-stable | tar xzvf -
pftbld-6.7-stable
pftbld-6.7-stable/LICENSE
pftbld-6.7-stable/README.md
pftbld-6.7-stable/docs
pftbld-6.7-stable/docs/mandoc.css
pftbld-6.7-stable/docs/pftblctl.8.html
pftbld-6.7-stable/docs/pftbld.8.html
pftbld-6.7-stable/docs/pftbld.conf.5.html
pftbld-6.7-stable/pkg
pftbld-6.7-stable/pkg/pftbld.conf
pftbld-6.7-stable/pkg/pftbld.rc
pftbld-6.7-stable/src
pftbld-6.7-stable/src/Makefile
pftbld-6.7-stable/src/config.c
pftbld-6.7-stable/src/listener.c
pftbld-6.7-stable/src/log.c
pftbld-6.7-stable/src/log.h
pftbld-6.7-stable/src/logger.c
pftbld-6.7-stable/src/parse.y
pftbld-6.7-stable/src/persist.c
pftbld-6.7-stable/src/pftblctl.8
pftbld-6.7-stable/src/pftblctl.sh
pftbld-6.7-stable/src/pftbld.8
pftbld-6.7-stable/src/pftbld.c
pftbld-6.7-stable/src/pftbld.conf.5
pftbld-6.7-stable/src/pftbld.h
pftbld-6.7-stable/src/scheduler.c
pftbld-6.7-stable/src/sockpipe.c
pftbld-6.7-stable/src/tinypfctl.c
pftbld-6.7-stable/src/util.c
```

Compile the sources and install the `pftbld` binary, the `pftblctl` tool and the manpages.

```
$ cd pftbld-6.7-stable/src
$ doas make obj
making /home/mpfr/pftbld-6.7-stable/src/obj
$ doas make
yacc  -o parse.c /home/mpfr/pftbld-6.7-stable/src/parse.y
cc -O2 -pipe  -Wall -I/home/mpfr/pftbld-6.7-stable/src -Wstrict-prototypes ...
.
.
.
cc   -o pftbld parse.o config.o listener.o log.o logger.o persist.o ...
$ doas make install
install -c -s  -o root -g bin  -m 555 pftbld /usr/local/sbin/pftbld
install -c -o root -g bin -m 555  /home/mpfr/pftbld-6.7-stable/src/pftblctl.sh ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-6.7-stable/src/pftblctl.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-6.7-stable/src/pftbld.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-6.7-stable/src/pftbld.conf.5 ...
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

Create a configuration file at the default location `/etc/pftbld/pftbld.conf`, e.g. by copying and adapting the [example](pkg/pftbld.conf) to your needs. When you're done, make sure to get the result verified.

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

The manpages of `pftbld(8)`, its configuration file `pftbld.conf(5)`, and its control tool `pftblctl(8)` are available either on the console or by pointing your browser to the corresponding `html` files under `pftbld-6.7-stable/docs/`.

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
