# kavsshvpn - SSH based tun reverse VPN

## Description

Local SNAT-ed server in private network with RFC1918 IP address can be
your VPN into LAN as "trojan horse". Program help make connection from
this server to Real-IP server in internet via SSH protocol and tune
routing table for all private subnets and work as MASQUERADE router
into LAN.

After that you can make OpenVPN, WireGuard or other classic VPN connection
with this internet server and use it as your own proxy-router into LAN.


## Help

```bash
$ ./kavcachefs -h
./kavsshvpn tun based VPN via SSH connection
Usage: ./kavsshvpn [options]
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
	-x "secretkeypass"
```

## TODO

- [ ] - option for retry reconnect after any fail
- [ ] - option for additional subnets routes in lAN
- [ ] - make connection as default route all traffic into LAN
- [ ] - hide private key password in 'ps aux'
