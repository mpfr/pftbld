# pftbld(8)

`pftbld(8)` is a lightweight [OpenBSD](https://www.openbsd.org) daemon written to automate [pf(4) table](http://man.openbsd.org/pf.conf#TABLES) content management and is typically used for building and maintaining dynamic firewall blocklists.

For further information, please have a look at the manpages of [pftbld(8)](https://mpfr.net/man/pftbld/6.9-stable/pftbld.8.html), its configuration file [pftbld.conf(5)](https://mpfr.net/man/pftbld/6.9-stable/pftbld.conf.5.html), and its control tool [pftblctl(8)](https://mpfr.net/man/pftbld/6.9-stable/pftblctl.8.html).

## How to interface

Other programs usually interact with `pftbld` by sending plain text messages to specified UNIX-domain sockets.

The most common cases probably are:
* [httpd(8)](http://man.openbsd.org/httpd)
	* via FastCGI as outlined in [pftbld.conf(5)](https://mpfr.net/man/pftbld/6.9-stable/pftbld.conf.5.html#EXAMPLES)
	* natively through the [httpd-plus](https://github.com/mpfr/httpd-plus#notify-on-block) add-on package
* [sshd(8)](http://man.openbsd.org/sshd)
	* by means of [saltan(8)](https://github.com/mpfr/saltan) which is tracking the authentication log file

## How to install

`pftbld` needs to be built from sources and installed manually. Luckily, this is easy and straightforward. Just follow the steps below.

First of all, make sure you're running `OpenBSD 6.9-stable`. Otherwise, one of the following branches might be more appropriate:
* [current](https://github.com/mpfr/pftbld)
* [6.8-stable](https://github.com/mpfr/pftbld/tree/6.8-stable)

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
$ doas rm -rf pftbld-6.9-stable/
$ ftp -Vo - https://codeload.github.com/mpfr/pftbld/tar.gz/6.9-stable | tar xzvf -
pftbld-6.9-stable
pftbld-6.9-stable/LICENSE
pftbld-6.9-stable/README.md
pftbld-6.9-stable/docs
pftbld-6.9-stable/docs/pftblctl.8.html
pftbld-6.9-stable/docs/pftbld.8.html
pftbld-6.9-stable/docs/pftbld.conf.5.html
pftbld-6.9-stable/pkg
pftbld-6.9-stable/pkg/pftbld.conf
pftbld-6.9-stable/pkg/pftbld.rc
pftbld-6.9-stable/src
pftbld-6.9-stable/src/Makefile
pftbld-6.9-stable/src/config.c
pftbld-6.9-stable/src/listener.c
pftbld-6.9-stable/src/log.c
pftbld-6.9-stable/src/log.h
pftbld-6.9-stable/src/logger.c
pftbld-6.9-stable/src/parse.y
pftbld-6.9-stable/src/persist.c
pftbld-6.9-stable/src/pftblctl.8
pftbld-6.9-stable/src/pftblctl.sh
pftbld-6.9-stable/src/pftbld.8
pftbld-6.9-stable/src/pftbld.c
pftbld-6.9-stable/src/pftbld.conf.5
pftbld-6.9-stable/src/pftbld.h
pftbld-6.9-stable/src/scheduler.c
pftbld-6.9-stable/src/sockpipe.c
pftbld-6.9-stable/src/tinypfctl.c
pftbld-6.9-stable/src/util.c
```

Compile the source files.

```
$ cd pftbld-6.9-stable/src
$ doas make
yacc  -o parse.c parse.y
cc -O2 -pipe  -Wall -I/home/mpfr/pftbld-6.9-stable/src -Wstrict-prototypes ...
.
.
.
cc   -o pftbld parse.o config.o listener.o log.o logger.o persist.o ...
```

Install daemon, manpages, service script, the daemon's user/group and a sample configuration file.

```
$ doas make fullinstall
install -c -s  -o root -g bin  -m 555 pftbld /usr/local/sbin/pftbld
install -c -o root -g bin -m 555  /home/mpfr/pftbld-6.9-stable/src/pftblctl.sh ...
install -c -o root -g bin -m 444  pftblctl.8 /usr/local/man/man8/pftblctl.8
install -c -o root -g bin -m 444  pftbld.8 /usr/local/man/man8/pftbld.8
install -c -o root -g bin -m 444  pftbld.conf.5 /usr/local/man/man5/pftbld.conf.5
install -c -o root -g bin -m 555  /home/mpfr/pftbld-6.9-stable/src/../pkg/pftbld...
useradd -c "pftbld unprivileged user" -d /var/empty -g =uid -r 100..999 -s ...
cp /home/mpfr/pftbld-6.9-stable/src/../pkg/pftbld.conf /etc/pftbld
```

> For further usage, the following list of available installation targets might be helpful:
> target name | description
> ----------- | -----------
> `fullinstall` | installs daemon, manpages, service script, user/group and a sample configuration file if a configuration file not yet exists
> `fulluninstall` | deletes everything installed by `fullinstall` but leaves the configuation file untouched if it was changed
> `install` | installs daemon and manpages only
> `reinstall` | runs `fulluninstall`, then `fullinstall`
> `uninstall` | deletes daemon and manpages
> `update` | compiles the sources and runs `fullinstall`

Activate the service script.

```
$ doas rcctl enable pftbld
```

Adapt the [sample](pkg/pftbld.conf) [configuration file](https://mpfr.net/man/pftbld/6.9-stable/pftbld.conf.5.html) at `/etc/pftbld/pftbld.conf` to your needs. Make sure your configuration is valid.

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

Uninstall daemon, manpages, service script and the daemon's user/group.

```
$ cd ~/pftbld-6.9-stable/src
$ doas make fulluninstall
rm /usr/local/sbin/pftbl* /usr/local/man/man{5,8}/pftbl*
rm /etc/rc.d/pftbld
userdel _pftbld
groupdel _pftbld
(configuration directory has changed, not touching /etc/pftbld)
```

Configuration and source directory need to be removed manually, if no longer needed.

```
$ doas rm -rf /etc/pftbld ~/pftbld-6.9-stable
```
