# kavsshvpn - SSH based tun reverse VPN

## Description

Local SNAT-ed server in private network with RFC1918 IP address can be
your VPN into LAN as "trojan horse". Program help make connection from
this server to Real-IP server in internet via SSH protocol and tune
routing table for all private subnets and work as MASQUERADE router
into LAN (with option `-t rfc1918`).

After that you can make OpenVPN, WireGuard or other classic VPN connection
with this internet server and use it as your own proxy-router into LAN.

Another case of usage is a share your connection via SSH for host
to access full internet (with `-t default`), or only with special subnets
or IP addresses (with `-t <subnet>`). This can help to manage servers
in protected areas without access to internet.

## Help

```bash
$ ./kavcachefs -h
./kavsshvpn tun based VPN via SSH connection
Usage: ./kavsshvpn [options]
	-f - foreground mode (daemonize by default)
	-s - work as server (connect to remote ssh)
	-c - work as client
	-n <subnet> - tun p-t-p /30 subnet (example: 10.254.254.0)
	-H <ip> - ssh host (example: 181.67.121.32)
	-P <port> - ssh port (default 22)
	-u <user> - ssh user (default root)
	-o <password> - password for ssh auth
	-a <id_rsa.pub> - public key file
	-b <id_rsa> - private key file
	-x <password> - private key password
	-r - permanent connection (retry after error)
	-w <sec> - wait between retry (default 15 sec)
	-t <subnet>|default|rfc1918 - add route on client
```

## Usage

Make reverse connection to Real-IP SSH server 111.222.33.44, up point-to-point
subnet [lan 10.254.254.1 --- inet 10.254.254.2], use for auth public key file
and password encrypted primary key.
```bash
$ sudo ./kavsshvpn -s \
	-H 111.222.33.44 \
	-P 22 \
	-n 10.254.254.0 \
	-a /home/user/.ssh/id_rsa.pub \
	-b /home/user/.ssh/id_rsa \
	-x "secretkeypass" \
	-t rfc1918
```

Share all routes for server 192.168.2.23:
```bash
$ sudo ./kavsshvpn -s \
	-H 192.168.2.23 \
	-P 22 \
	-n 10.254.253.0 \
	-a /home/admin/.ssh/id_rsa.pub \
	-b /home/admin/.ssh/id_rsa \
	-t default
```

Share only specified subnet 10.168.1.0/24 for server:
```bash
$ sudo ./kavsshvpn -s \
	-H 111.222.33.44 \
	-P 22 \
	-n 10.254.252.0 \
	-a /home/admin/.ssh/id_rsa.pub \
	-b /home/admin/.ssh/id_rsa \
	-t 10.168.1.0/24
```

## Build

Prepare new empty cloud server with Ubuntu 22.04 for build and run kavsshvpn
as Real-IP server.

```bash

$ sudo apt update && sudo apt upgrade
$ reboot

$ sudo apt install -y iptables
$ sudo apt install -y build-essential
$ sudo apt install -y git
$ sudo apt install -y pkg-config libssh2-1-dev
```

Clone and build:
```bash
$ git clone https://github.com/KuzinAndrey/kavsshvpn.git
$ cd kavsshvpn
$ ./build prod
$ cp ./kavsshvpn /bin/kavsshvpn
```

## TODO

- [x] - option for retry reconnect after any fail
- [x] - option for additional subnets routes in LAN
- [x] - make connection as default route all traffic into LAN
- [ ] - hide private key password in 'ps aux'

## Useful links

- [libssh2](https://github.com/libssh2/libssh2) - SSH2 library
- [openvpn-install](https://github.com/Nyr/openvpn-install) - OpenVPN road warrior installer for Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora.
- [wireguard-install](https://github.com/Nyr/wireguard-install) - WireGuard road warrior installer for Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora.

## Some common SSH problems with old libssh2 versions

1. Old libssh2 client library 1.8.0 on Linux Mint 20.1 make authentication via ssh-rsa and get error:

```
Can't make ssh handshake - -5.
libssh2 error: -5 - Unable to exchange encryption keys
```
In remote server logs by `journalctl -f` get some errors:
```
Apr 21 16:44:15 host.example.com sshd[4046]: Unable to negotiate with XXX.XXX.XXX.XXX port 39442: no matching host key type found. Their offer: ssh-rsa,ssh-dss [preauth]
```
Solve problem with add to /etc/ssh/sshd_config on SSH server:
```
PubkeyAuthentication yes
HostKeyAlgorithms +ssh-rsa
PubkeyAcceptedKeyTypes=+ssh-rsa
```
And restart the sshd daemon by command:
```
$ sudo systemctl restart sshd
```

2. Wrong format of public/private key file

New key files identifies as `-----BEGIN OPENSSH PRIVATE KEY-----` instead of the older keys identified
as `-----BEGIN RSA PRIVATE KEY-----`. In older version of libssh2 1.8.0 we can get an error:
```
Auth as "root" by public key: /home/user/.ssh/id_rsa.pub
Auth by public key failed.
libssh2 error: -19 - Callback returned error
Close ssh socket #4
```
TO solve this problem we need to generate new private/public key file in PEM format by run command:
```
$ ssh-keygen -m PEM -t rsa -f /home/user/.ssh/id_rsa_pem
```
And save this new public key on server by `ssh-copy-id` or manually in `~/.ssh/authorized_keys` file.

