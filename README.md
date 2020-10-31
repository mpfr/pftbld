# pftbld

`pftbld` is a lightweight [OpenBSD](https://www.openbsd.org) daemon written to automate [pf(4) table](http://man.openbsd.org/pf.conf#TABLES) content management and is typically used for maintaining dynamic firewall blacklists.

For further information, please have a look at the manpages of [pftbld(8)](https://mpfr.github.io/pftbld/pftbld.8.html), its configuration file [pftbld.conf(5)](https://mpfr.github.io/pftbld/pftbld.conf.5.html), and its control tool [pftblctl(8)](https://mpfr.github.io/pftbld/pftblctl.8.html).

## How to install

`pftbld` needs to be built from sources and installed manually. Luckily, this is easy and straightforward. Just follow the steps below.

First of all, make sure you're running `OpenBSD-current`. Otherwise, one of the following branches might be more appropriate:
* [6.8-stable](https://github.com/mpfr/pftbld/tree/6.8-stable)
* [6.7-stable](https://github.com/mpfr/pftbld/tree/6.7-stable)

Then, make sure your user (e.g. `mpfr`) has sufficient `doas` permissions.

```
$ cat /etc/doas.conf
permit nopass mpfr
```

Download and extract the source files into the user's home directory, here `/home/mpfr`.

```
$ cd
$ pwd
/home/mpfr
$ doas rm -rf pftbld-current/
$ ftp -Vo - https://codeload.github.com/mpfr/pftbld/tar.gz/current | tar xzvf -
pftbld-current
pftbld-current/LICENSE
pftbld-current/README.md
pftbld-current/docs
pftbld-current/docs/mandoc.css
pftbld-current/docs/pftblctl.8.html
pftbld-current/docs/pftbld.8.html
pftbld-current/docs/pftbld.conf.5.html
pftbld-current/pkg
pftbld-current/pkg/pftbld.conf
pftbld-current/pkg/pftbld.rc
pftbld-current/src
pftbld-current/src/Makefile
pftbld-current/src/config.c
pftbld-current/src/listener.c
pftbld-current/src/log.c
pftbld-current/src/log.h
pftbld-current/src/logger.c
pftbld-current/src/parse.y
pftbld-current/src/persist.c
pftbld-current/src/pftblctl.8
pftbld-current/src/pftblctl.sh
pftbld-current/src/pftbld.8
pftbld-current/src/pftbld.c
pftbld-current/src/pftbld.conf.5
pftbld-current/src/pftbld.h
pftbld-current/src/scheduler.c
pftbld-current/src/sockpipe.c
pftbld-current/src/tinypfctl.c
pftbld-current/src/util.c
```

Compile the source files.

```
$ cd pftbld-current/src
$ doas make obj
making /home/mpfr/pftbld-current/src/obj
$ doas make
yacc  -o parse.c /home/mpfr/pftbld-current/src/parse.y
cc -O2 -pipe  -Wall -I/home/mpfr/pftbld-current/src -Wstrict-prototypes ...
.
.
.
cc   -o pftbld parse.o config.o listener.o log.o logger.o persist.o ...
```

Install the daemon, related files, manpages and the daemon's user/group.

```
$ doas make fullinstall
install -c -s  -o root -g bin  -m 555 pftbld /usr/local/sbin/pftbld
install -c -o root -g bin -m 555  /home/mpfr/pftbld-current/src/pftblctl.sh ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-current/src/pftblctl.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-current/src/pftbld.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-current/src/pftbld.conf.5 install -c -o root -g bin -m 555  /home/mpfr/pftbld-current/src/../pkg/pftbld.rc ...
useradd -c "pftbld unprivileged user" -d /var/empty -g =uid -r 100..999 -s /sbin/nologin _pftbld
cp /home/mpfr/pftbld-current/src/../pkg/pftbld.conf /etc/pftbld
```

Activate the service script.

```
$ doas rcctl enable pftbld
```

Adapt the sample [configuration file](https://mpfr.github.io/pftbld/pftbld.conf.5.html) at `/etc/pftbld/pftbld.conf` to your needs. When you're done, make sure to get the result verified.

```
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

Stop the `pftbld` daemon.

```
$ doas rcctl stop pftbld
pftbld(ok)
```

Deactivate the service script.

```
$ doas rcctl disable pftbld
```

Uninstall the daemon, related files, manpages and the daemon's user/group.

```
$ cd ~/pftbld-current/src
$ doas make uninstall
rm -f /etc/rc.d/pftbld /usr/local/man/man{5,8}/pftbl* /usr/local/sbin/pftbl*
userdel _pftbld
groupdel _pftbld
configuration has changes, not touching /etc/pftbld
```
