# pftbld

`pftbld` is a lightweight [OpenBSD](https://www.openbsd.org) daemon written to automate [pf(4) table](http://man.openbsd.org/pf.conf#TABLES) content management and is typically used for maintaining dynamic firewall blacklists.

## How to install

`pftbld` needs to be built from sources and installed manually. Luckily, this is easy and straightforward. Just follow the steps below.

Make sure you're running `OpenBSD 6.8-stable`. Otherwise, one of the following branches might be more appropriate:
* [current](https://github.com/mpfr/pftbld)
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
$ doas rm -rf pftbld-6.8-stable/
$ ftp -Vo - https://codeload.github.com/mpfr/pftbld/tar.gz/6.8-stable | tar xzvf -
pftbld-6.8-stable
pftbld-6.8-stable/LICENSE
pftbld-6.8-stable/README.md
pftbld-6.8-stable/docs
pftbld-6.8-stable/docs/mandoc.css
pftbld-6.8-stable/docs/pftblctl.8.html
pftbld-6.8-stable/docs/pftbld.8.html
pftbld-6.8-stable/docs/pftbld.conf.5.html
pftbld-6.8-stable/pkg
pftbld-6.8-stable/pkg/pftbld.conf
pftbld-6.8-stable/pkg/pftbld.rc
pftbld-6.8-stable/src
pftbld-6.8-stable/src/Makefile
pftbld-6.8-stable/src/config.c
pftbld-6.8-stable/src/listener.c
pftbld-6.8-stable/src/log.c
pftbld-6.8-stable/src/log.h
pftbld-6.8-stable/src/logger.c
pftbld-6.8-stable/src/parse.y
pftbld-6.8-stable/src/persist.c
pftbld-6.8-stable/src/pftblctl.8
pftbld-6.8-stable/src/pftblctl.sh
pftbld-6.8-stable/src/pftbld.8
pftbld-6.8-stable/src/pftbld.c
pftbld-6.8-stable/src/pftbld.conf.5
pftbld-6.8-stable/src/pftbld.h
pftbld-6.8-stable/src/scheduler.c
pftbld-6.8-stable/src/sockpipe.c
pftbld-6.8-stable/src/tinypfctl.c
pftbld-6.8-stable/src/util.c
```

Compile the source files.

```
$ cd pftbld-6.8-stable/src
$ doas make obj
making /home/mpfr/pftbld-6.8-stable/src/obj
$ doas make
yacc  -o parse.c /home/mpfr/pftbld-6.8-stable/src/parse.y
cc -O2 -pipe  -Wall -I/home/mpfr/pftbld-6.8-stable/src -Wstrict-prototypes ...
.
.
.
cc   -o pftbld parse.o config.o listener.o log.o logger.o persist.o ...
```

Install the daemon, related files, manpages and the daemon's user/group.

```
$ doas make fullinstall
install -c -s  -o root -g bin  -m 555 pftbld /usr/local/sbin/pftbld
install -c -o root -g bin -m 555  /home/mpfr/pftbld-6.8-stable/src/pftblctl.sh ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-6.8-stable/src/pftblctl.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-6.8-stable/src/pftbld.8 ...
install -c -o root -g bin -m 444  /home/mpfr/pftbld-6.8-stable/src/pftbld.conf.5 ...
install -c -o root -g bin -m 555  /home/mpfr/pftbld-6.8-stable/src/../pkg/pftbld...
useradd -c "pftbld unprivileged user" -d /var/empty -g =uid -r 100..999 -s ...
cp /home/mpfr/pftbld-6.8-stable/src/../pkg/pftbld.conf /etc/pftbld
```

Activate the service script.

```
$ doas rcctl enable pftbld
```

Adapt the [sample](pkg/pftbld.conf) configuration file at `/etc/pftbld/pftbld.conf` to your needs. When you're done, make sure to get the result verified.

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

> The manpages of `pftbld(8)`, its configuration file `pftbld.conf(5)`, and its control tool `pftblctl(8)` are available either on the console or by pointing your browser to the corresponding `html` files under `pftbld-6.8-stable/docs/`.

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
$ cd ~/pftbld-6.8-stable/src
$ doas make uninstall
rm -f /etc/rc.d/pftbld /usr/local/man/man{5,8}/pftbl* /usr/local/sbin/pftbl*
userdel _pftbld
groupdel _pftbld
configuration has changes, not touching /etc/pftbld
```
