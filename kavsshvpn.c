/*
///////////////////////////////////////////////////////

kavsshvpn - SSH based tun reverse VPN

Author: kuzinandrey@yandex.ru

URL: https://www.github.com/KuzinAndrey/kavsshvpn

///////////////////////////////////////////////////////

Dependency:
    libssh2 - library for SSH communication

Build:
    LIBSSH2=$(pkg-config libssh2 --cflags --libs)
    gcc -Wall -s -DPRODUCTION=1 -pedantic kavsshvpn.c $LIBSSH2 -o kavsshvpn

Run:
    sudo ./kavsshvpn -r -s -n 10.254.254.0 -H 111.110.11.22 \
      -a /home/user/.ssh/id_rsa.pub \
      -b /home/user/.ssh/id_rsa \
      -x "secretprikeypass" \
      -t rfc1918

History:
   2024-04-21 - Initial version
   2024-04-24 - Refactor code from multithreaded style, because at high traffic
       buffer overflow occured in SSH library and rise assert with SIGABRT.
   2024-04-25 - Add more read/write return checks for stable work.
       Add -w parameter to set retry delay between reconnections to SSH server.
   2024-06-22 - Add parameter -t to manage client routing table (now by default
       don't change any routes on target host)
   2024-09-24 - Some useful changes:
        * find path for iptables and ip command
        * save system ipv4 forward status at start (prevent broke already working linux routers)
        * add run modprobe for tun driver
        * option for invert forwarding roles (for work as classic VPN then
          you connect to server, because in our terms SSH server you connected
          to is a "client")
///////////////////////////////////////////////////////
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include <libssh2.h>

#ifndef PRODUCTION
#define TRACE fprintf(stderr,"TRACE %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define TRACE
#define DEBUG(...)
#endif

#ifndef LIBSSH2_HOSTKEY_HASH_SHA1_LEN
#define LIBSSH2_HOSTKEY_HASH_SHA1_LEN 20
#endif

int program_state = 0; // 2 - exit
int run_command(const char *fmt, ...);

///////////////////////////////////////////////////////
//////// TUN
///////////////////////////////////////////////////////

struct tun_connection {
	int tun_fd;
	char tun_name[IFNAMSIZ];
};

// OPEN TUN DEVICE (return -1 if error)
int up_tun_iface(struct tun_connection *conn, const char *name) {
	struct ifreq ifr;
	int retry = 0;

	if (!conn || !name) return -1;

retry:
	if ((conn->tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
		fprintf(stderr,"Can't open /dev/net/tun: %s\n", strerror(errno));
		if (errno == ENOENT) {
			if (0 == run_command("modprobe tun") && !retry) {
				retry++;
				goto retry;
			}
		}
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(conn->tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
		fprintf(stderr,"Can't ioctl: %s\n", strerror(errno));
		return -1;
	}

	strcpy(conn->tun_name, ifr.ifr_name);
	DEBUG("Open tun device: %s\n",conn->tun_name);

	return 0;
} // up_tun_iface()

// CLOSE TUN DEVICE
int down_tun_iface(struct tun_connection *conn) {
	int ret = -1;
	if (conn && conn->tun_fd > 2) {
		ret = close(conn->tun_fd);
		if (ret == 0) conn->tun_fd = 0;
	}
	return ret;
} // down_tun_iface()

///////////////////////////////////////////////////////
//////// SSH
///////////////////////////////////////////////////////
struct ssh_session {
	libssh2_socket_t sock;
	struct sockaddr_in sin;
	char *user;
	char *pubkey;
	char *privkey;
	char *keypass;
	char *password;
	char *server_ip;
	in_port_t port;
	LIBSSH2_SESSION *session;
	LIBSSH2_LISTENER *listener;
	LIBSSH2_CHANNEL *channel;
};

static int ssh_waitsocket(libssh2_socket_t socket_fd, LIBSSH2_SESSION *session)
{
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 100000 };
	fd_set fd;
	fd_set *writefd = NULL;
	fd_set *readfd = NULL;
	int dir;

	FD_ZERO(&fd);
	FD_SET(socket_fd, &fd);
	dir = libssh2_session_block_directions(session);
	if(dir & LIBSSH2_SESSION_BLOCK_INBOUND) readfd = &fd;
	if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) writefd = &fd;
	return select((int)(socket_fd + 1), readfd, writefd, NULL, &timeout);
} // ssh_waitsocket()

void clean_ssh_session(struct ssh_session *sess) {
	if (!sess) return;

	if (sess->session) {
		libssh2_session_disconnect(sess->session, "Normal Shutdown");
		libssh2_session_free(sess->session);
		sess->session = NULL;
	}

	if (sess->sock != LIBSSH2_INVALID_SOCKET) {
		fprintf(stderr,"Close ssh socket #%d\n", sess->sock);
		shutdown(sess->sock, SHUT_RDWR);
		close(sess->sock);
		sess->sock = LIBSSH2_INVALID_SOCKET;
	}

	if (sess->server_ip) { free(sess->server_ip); sess->server_ip = NULL; }
	if (sess->user) { free(sess->user); sess->user = NULL; }
	if (sess->password) { free(sess->password); sess->password = NULL; }
	if (sess->pubkey) { free(sess->pubkey); sess->pubkey = NULL; }
	if (sess->privkey) { free(sess->privkey); sess->privkey = NULL; }
	if (sess->keypass) { free(sess->keypass); sess->keypass = NULL; }
} // clean_ssh_session()

int up_ssh_session(struct ssh_session *sess) {
	int rc = 0;
	char *err = NULL;

	if (!sess->user || !sess->server_ip) {
		fprintf(stderr,"No some SSH session parameters\n");
		goto return_error;
	}

	sess->sin.sin_family = AF_INET;
	sess->sin.sin_addr.s_addr = inet_addr(sess->server_ip);
	if (INADDR_NONE == sess->sin.sin_addr.s_addr) {
		fprintf(stderr,"Can't parse server ip \"%s\" for ssh session\n", sess->server_ip);
		goto return_error;
	}

	sess->sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sess->sock == LIBSSH2_INVALID_SOCKET) {
		fprintf(stderr,"Can't create socket for ssh session\n");
		goto return_error;
	}

	sess->sin.sin_port = htons(sess->port);
	if (connect(sess->sock, (struct sockaddr*)(&sess->sin), sizeof(struct sockaddr_in))) {
		fprintf(stderr, "Can't make tcp connection to %s:%d - %s\n",
			inet_ntoa(sess->sin.sin_addr), ntohs(sess->sin.sin_port),
			strerror(errno));
		goto return_error;
	}

	sess->session = libssh2_session_init();
	if (!sess->session) {
		fprintf(stderr,"Can't init SSH session.\n");
		goto return_error;
	}

	libssh2_session_set_blocking(sess->session, 0); // non-blocking mode
	libssh2_keepalive_config(sess->session, 1, 30);

	while ((rc = libssh2_session_handshake(sess->session, sess->sock)) ==
		LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		fprintf(stderr,"Can't make ssh handshake - %d.\n", rc);
		goto return_error;
	}

	const char *fingerprint = libssh2_hostkey_hash(sess->session,
		LIBSSH2_HOSTKEY_HASH_SHA1);
	if (!fingerprint) {
		fprintf(stderr,"Can't get SSH server SHA1 fingerprint.\n");
		goto return_error;
	}

	fprintf(stderr,"SSH server fingerprint: ");
	for (int i = 0; i < LIBSSH2_HOSTKEY_HASH_SHA1_LEN; i++)
		fprintf(stderr,"%02X", (unsigned char)fingerprint[i]);
	fprintf(stderr,"\n");

	char *userauthlist = NULL;
	do {
		userauthlist = libssh2_userauth_list(sess->session, sess->user, strlen(sess->user));
		if (userauthlist ||
			LIBSSH2_ERROR_EAGAIN != libssh2_session_last_error(
				sess->session, NULL, NULL, 0)) break;

		ssh_waitsocket(sess->sock, sess->session);
	} while(1);
	if (!userauthlist) {
		fprintf(stderr,"Can't get SSH auth methods list for user \"%s\".\n", sess->user);
		goto return_error;
	}

	fprintf(stderr, "SSH auth methods list: %s\n", userauthlist);

	if (strstr(userauthlist, "publickey") && sess->pubkey && sess->privkey) {
		fprintf(stderr, "Auth as \"%s\" by public key: %s\n", sess->user, sess->pubkey);
		while ((rc = libssh2_userauth_publickey_fromfile(sess->session,
			sess->user, sess->pubkey, sess->privkey, sess->keypass))
			== LIBSSH2_ERROR_EAGAIN) {};
		if (rc) {
			fprintf(stderr,"Auth by public key failed.\n");
			goto return_error;
		}
	} else if (strstr(userauthlist, "password") && sess->password) {
		fprintf(stderr, "Auth as \"%s\" by password.\n", sess->user);
		while ((rc = libssh2_userauth_password(sess->session, sess->user,
			sess->password)) == LIBSSH2_ERROR_EAGAIN) {};
		if (rc) {
			fprintf(stderr,"Auth by password failed.\n");
			goto return_error;
		}
	} else {
		fprintf(stderr,"Can't find any valid auth methods.\n");
		goto return_error;
	}

	fprintf(stderr,"Auth successful.\n");
	return 0;

return_error:
	rc = libssh2_session_last_error(sess->session, &err, NULL, 0);
	fprintf(stderr,"libssh2 error: %d - %s\n", rc, err);
	clean_ssh_session(sess);
	return 1;
} // up_ssh_session()

void clean_ssh_channel(struct ssh_session *sess) {
	if (!sess || !sess->session || !sess->channel) return;
	int rc;
//	int exitcode;

	while (( rc = libssh2_channel_close(sess->channel)) == LIBSSH2_ERROR_EAGAIN) {
		ssh_waitsocket(sess->sock, sess->session);
	}

//	if (rc == 0) {
//		exitcode = libssh2_channel_get_exit_status(sess->channel);
//		// TODO ?
//	}

	libssh2_channel_free(sess->channel);
	sess->channel = NULL;
} // clean_ssh_channel()

int up_ssh_channel(struct ssh_session *sess) {
	if (!sess) return 1;
	if (!sess->session) return 1;

	do {
		sess->channel = libssh2_channel_open_session(sess->session);
		if (sess->channel ||
			LIBSSH2_ERROR_EAGAIN != libssh2_session_last_error(
				sess->session, NULL, NULL, 0)) break;

		ssh_waitsocket(sess->sock, sess->session);
	} while(1);

	if (!sess->channel) {
		char *err = NULL;
		int rc = libssh2_session_last_error(sess->session, &err, NULL, 0);
		fprintf(stderr,"libssh2 channel error: %d - %s\n", rc, err);
		return 1;
	}

	return 0;
} // up_ssh_channel()

int run_command(const char *fmt, ...) {
	char *com = NULL;
	int comret = 0;
	int ret = -1; // default error

	va_list arg_list;
	va_start(arg_list, fmt);
	ret = vasprintf(&com, fmt, arg_list);
	va_end(arg_list);
	if (ret == -1) goto defer;

	printf("+ %s",com);
	comret = system(com);
	printf(" = %d\n", comret);
	if (comret == -1) {
		fprintf(stderr, "Can't run command: \"%s\" - %s\n", com, strerror(errno));
	} else if (comret != 0) {
		fprintf(stderr, "Command \"%s\" return not zero code %d\n", com, comret);
	} else ret = comret;
defer:
	if (com) free(com);
	return ret;
} // run_command()

void signal_handler(int sig) {
	switch (sig) {
		case SIGINT:
		case SIGTERM:
			program_state = 3; //exit main cycle
		break;
	} // swtich
} // signal_handler()

///////////////////////////////////////////////////////
//////// CONFIG
///////////////////////////////////////////////////////
enum work_mode_en {
	WORK_MODE_UNKNOWN = 0,
	WORK_MODE_SERVER,
	WORK_MODE_CLIENT,
} work_mode = WORK_MODE_UNKNOWN;

char *opt_ptp_subnet = NULL;
struct in_addr tun_ptp_subnet;
char *opt_ssh_host = NULL;
in_port_t opt_ssh_port = 22;
char *opt_ssh_user = NULL;
char *opt_ssh_password = NULL;
char *opt_ssh_privkey = NULL;
char *opt_ssh_pubkey = NULL;
char *opt_ssh_keypass = NULL;

int opt_foreground = 0;
int opt_server_permanent = 0;
int opt_server_retry_wait = 15;

int opt_client_route_default = 0;
int opt_client_route_rfc1918 = 0;
char *opt_client_routes = NULL;
size_t opt_client_routes_count = 0;
char *client_default_route_delete_command = NULL;

const char *session_start_sign = "ReAdy-SeT-Go!\n";
struct tun_connection tc = {0};
struct ssh_session sshconn = {0};

char *tun_buffer = NULL;
size_t tun_buffer_size = 32 << 10;
char *channel_buffer = NULL;
size_t channel_buffer_size = 32 << 10;

int ip_forward_state = 0;
#define PROC_IPV4_IP_FORWARD "/proc/sys/net/ipv4/ip_forward"

char *vpncmd = NULL;

#define PROC_NET_ROUTE_PATH "/proc/net/route"

int opt_invert_roles = 0;

const char *iptables_bin = NULL;
const char *iptables_search[] = {
	"/usr/local/sbin/iptables",
	"/usr/local/bin/iptables",
	"/usr/sbin/iptables",
	"/usr/bin/iptables",
	"/sbin/iptables",
	"/usr/iptables",
	NULL };

const char *ip_bin = NULL;
const char *ip_search[] = {
	"/usr/local/sbin/ip",
	"/usr/local/bin/ip",
	"/usr/sbin/ip",
	"/usr/bin/ip",
	"/sbin/ip",
	"/usr/ip",
	NULL };


///////////////////////////////////////////////////////
// CLIENT/SERVER WORK
///////////////////////////////////////////////////////

int client_work(struct tun_connection *conn) {
	int rc;

	ssize_t n;
	size_t packet_size;
	size_t pos;
	size_t nw;

	int channel_state = 0; // 0 - read packet size, 1 - read packet
	size_t channel_packet_size = 0;
	size_t channel_state_pos = 0;

	// we need send info about packet length in ssh stream (reserve at buffer start size_t space)
	char *adj_buffer = tun_buffer + sizeof(packet_size);
	size_t adj_buffer_size = tun_buffer_size - sizeof(packet_size);

	fd_set rfds;
	struct timeval tv;

	// send SIGN to server for detect session start
	fprintf(stdout, "%s", session_start_sign);
	fflush(stdout);

	while (1) {
		// READ FROM TUN
		FD_ZERO(&rfds);
		FD_SET(conn->tun_fd,&rfds);
		tv.tv_sec = 0; tv.tv_usec = 1000;
		rc = select((conn->tun_fd + 1), &rfds, NULL, NULL, &tv);
		if ( -1 == rc ) return -__LINE__;
		if (rc && FD_ISSET(conn->tun_fd, &rfds)) {
			n = read(conn->tun_fd, adj_buffer, adj_buffer_size);
			if (n < 0) {
				if ( errno == EINTR || errno == EAGAIN ) continue;
				return -__LINE__;
			} else if (n == 0) return -__LINE__;

			// save info about packet size
			pos = htonl(n);
			memcpy(tun_buffer, &pos, sizeof(size_t));

			packet_size = n + sizeof(pos); // packet size for write to ssh channel

			pos = 0;
			do {
				nw = fwrite(tun_buffer + pos, 1, packet_size - pos, stdout);
				if (nw == 0 && ferror(stdout)) return -__LINE__;
				pos += nw;
			} while (packet_size - pos > 0);
			fflush(stdout);
		} // if tun can read

		// READ FROM STDIN
		if (channel_state == 0) { // read packet size
			FD_ZERO(&rfds);
			FD_SET(STDIN_FILENO,&rfds);
			tv.tv_sec = 0; tv.tv_usec = 1000;
			rc = select((STDIN_FILENO + 1), &rfds, NULL, NULL, &tv);
			if ( -1 == rc ) return -__LINE__;
			if (rc && FD_ISSET(STDIN_FILENO, &rfds)) {
				n = read(STDIN_FILENO, (char *)&channel_packet_size + channel_state_pos,
					sizeof(channel_packet_size) - channel_state_pos);
				if (n < 0) {
					if ( errno == EINTR || errno == EAGAIN ) continue;
					return -__LINE__;
				} else if (n == 0) return -__LINE__;
				channel_state_pos += n;

				if (channel_state_pos == sizeof(channel_packet_size)) {
					channel_state = 1; // read packet
					channel_state_pos = 0;
					channel_packet_size = ntohl(channel_packet_size);
					// adjust buffer size
					if (channel_packet_size > channel_buffer_size) {
						char *r = realloc(channel_buffer, channel_packet_size);
						if (!r) {
							// TODO no memory log
							return -__LINE__;
						}
						channel_buffer = r;
						channel_buffer_size = channel_packet_size;
					}
				}
			} // if can read
		}

		while (channel_state == 1) { // read packet content
			FD_ZERO(&rfds);
			FD_SET(STDIN_FILENO,&rfds);
			tv.tv_sec = 0; tv.tv_usec = 1000;
			rc = select((STDIN_FILENO + 1), &rfds, NULL, NULL, &tv);
			if ( -1 == rc ) return -__LINE__;
			if (rc && FD_ISSET(STDIN_FILENO, &rfds)) {
				n = read(STDIN_FILENO, channel_buffer + channel_state_pos,
					channel_packet_size - channel_state_pos);
				if (n < 0) {
					if ( errno == EINTR || errno == EAGAIN ) continue;
					return -__LINE__;
				} else if (n == 0) return -__LINE__;
				channel_state_pos += n;
				if (channel_state_pos == channel_packet_size) {
					channel_state = 2; // write packet to tun
					channel_state_pos = 0;
				}
			} // if can read
		} // state == 1

		while (channel_state == 2) { // write packet to tun
			n = write(conn->tun_fd, channel_buffer + channel_state_pos,
				channel_packet_size - channel_state_pos);
			if (n < 0) {
				if ( errno == EINTR || errno == EAGAIN ) continue;
				return -__LINE__;
			};
			channel_state_pos += n;

			if (channel_packet_size - channel_state_pos == 0) {
				channel_state = 0; // read packet size mode
				channel_state_pos = 0;
				channel_packet_size = 0;
			}
		} // state == 2

		if (program_state != 1) break;
	} // while

	return 0;
} // client_work()

int server_work(struct tun_connection *conn, struct ssh_session *sess) {
	int rc;
	ssize_t n;

	size_t packet_size;
	size_t pos;

	int channel_state = 0; // 0 - read packet size, 1 - read packet
	size_t channel_packet_size = 0;
	size_t channel_state_pos = 0;

	// we need send info about packet length in ssh stream (reserve at buffer start size_t space)
	char *adj_buffer = tun_buffer + sizeof(packet_size);
	size_t adj_buffer_size = tun_buffer_size - sizeof(packet_size);

	fd_set rfds;
	struct timeval tv;

	while (1) {
		// READ FROM TUN
		FD_ZERO(&rfds);
		FD_SET(conn->tun_fd,&rfds);
		tv.tv_sec = 0; tv.tv_usec = 1000;
		rc = select((conn->tun_fd + 1), &rfds, NULL, NULL, &tv);
		if ( -1 == rc ) return -__LINE__;
		if (rc && FD_ISSET(conn->tun_fd, &rfds)) {
			n = read(conn->tun_fd, adj_buffer, adj_buffer_size);
			if (n <= 0) return -__LINE__;

			// save info about packet size
			pos = htonl(n);
			memcpy(tun_buffer, &pos, sizeof(size_t));

			pos = 0;
			packet_size = n + sizeof(pos); // packet size for write to ssh channel
			do {
				n = libssh2_channel_write(sess->channel,
					tun_buffer + pos, packet_size - pos);
				if (n == LIBSSH2_ERROR_EAGAIN) continue;
				else if (n < 0) return -__LINE__;
				pos += n;
			} while (packet_size - pos > 0);
		} // if tun can read

		// READ FROM SSH CHANNEL
		if (channel_state == 0) { // read packet size from ssh channel
			n = libssh2_channel_read(sess->channel,
				(char *)(&channel_packet_size) + channel_state_pos,
				sizeof(channel_packet_size) - channel_state_pos);
			if (n == LIBSSH2_ERROR_EAGAIN) {
				continue;
			} else if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
				break;
			} else if (n < 0) {
				// TODO error log
				return -__LINE__;
			}
			channel_state_pos += n;
			if (sizeof(channel_packet_size) - channel_state_pos == 0) {
				// after read packet size prepare to read whole packet
				channel_state = 1;
				channel_state_pos = 0;
				channel_packet_size = ntohl(channel_packet_size);

				// adjust buffer size
				if (channel_packet_size > channel_buffer_size) {
					char *r = realloc(channel_buffer, channel_packet_size);
					if (!r) {
						// TODO no memory log
						return -__LINE__;
					}
					channel_buffer = r;
					channel_buffer_size = channel_packet_size;
				}
			} // if readed
		} // if state == 0
		if (n < 0 && libssh2_channel_eof(sess->channel)) break;

		while (channel_state == 1) { // read packet from ssh channel
			n = libssh2_channel_read(sess->channel,
				channel_buffer + channel_state_pos,
				channel_packet_size - channel_state_pos);
			if (n == LIBSSH2_ERROR_EAGAIN) {
				continue;
			} else if (n == LIBSSH2_ERROR_CHANNEL_CLOSED) {
				break;
			} else if (n < 0) {
				// TODO error log
				return -__LINE__;
			}
			channel_state_pos += n;
			if (channel_packet_size - channel_state_pos == 0) {
				channel_state = 2; // write packet to tun mode
				channel_state_pos = 0;
			}
		} // state == 1
		if (n < 0 && libssh2_channel_eof(sess->channel)) break;

		while (channel_state == 2) { // write packet to tun
			n = write(conn->tun_fd, channel_buffer + channel_state_pos,
				channel_packet_size - channel_state_pos);
			if (n < 0) {
				if ( errno == EINTR || errno == EAGAIN ) continue;
				return -__LINE__;
			};
			channel_state_pos += n;

			if (channel_packet_size - channel_state_pos == 0) {
				channel_state = 0; // read packet size mode
				channel_state_pos = 0;
				channel_packet_size = 0;
			}
		} // state == 2

		if (program_state != 1) break; // program not in work mode
	} // while

	return 0;
} // server_work()

///////////////////////////////////////////////////////
// MAIN
///////////////////////////////////////////////////////

void print_help(const char *prog) {
	printf("%s tun based VPN via SSH connection\n", prog);
	printf("Usage: %s [options]\n", prog);
	printf("\t-f - foreground mode (daemonize by default)\n");
	printf("\t-s - work as server (connect to remote ssh)\n");
	printf("\t-c - work as client\n");
	printf("\t-i - invert roles (client in forwarding mode)\n");
	printf("\t-n <subnet> - tun p-t-p /30 subnet (example: 10.254.254.0)\n");
	printf("\t-H <ip> - ssh host (example: 181.67.121.32)\n");
	printf("\t-P <port> - ssh port (default 22)\n");
	printf("\t-u <user> - ssh user (default root)\n");
	printf("\t-o <password> - password for ssh auth\n");
	printf("\t-a <id_rsa.pub> - public key file\n");
	printf("\t-b <id_rsa> - private key file\n");
	printf("\t-x <password> - private key password\n");
	printf("\t-r - permanent connection (retry after error)\n");
	printf("\t-w <sec> - wait between retry (default 15 sec)\n");
	printf("\t-t <subnet>|default|rfc1918 - add route on client\n");
	exit(0);
} // print_help()


char *get_default_gateway(char *buffer) {
	FILE *net_route = fopen(PROC_NET_ROUTE_PATH,"r");
	if (!net_route) {
		fprintf(stderr,"can't open file %s\n",PROC_NET_ROUTE_PATH);
		return NULL;
	}

	char skip_header[128];
	if (!fgets(skip_header, sizeof(skip_header), net_route)) {
		fprintf(stderr,"can't skip header of %s\n",PROC_NET_ROUTE_PATH);
		fclose(net_route);
		return NULL;
	}

	char routeif_name[IFNAMSIZ];
	struct in_addr route_net;
	struct in_addr route_mask;
	struct in_addr route_gw;
	unsigned int no;
	int s;

	sprintf(buffer, "%s", ""); // default empty

	while (1) {
		s = fscanf(net_route, "%s\t%X\t%X\t%X\t%u\t%u\t%u\t%X\t%u\t%u\t%u",
		routeif_name, &route_net.s_addr, &route_gw.s_addr, &no, &no, &no, &no,
		&route_mask.s_addr, &no, &no, &no);

		if (s != 11) break;
		//printf("read %d %s %d\n", s, routeif_name, IFNAMSIZ);

		if (route_net.s_addr == 0 && route_mask.s_addr == 0) {
			sprintf(buffer,"%s", inet_ntoa(route_gw));
		}
		//printf("iface: %s,", routeif_name);
		//printf(" dst %s,", inet_ntoa(route_net));
		//printf(" mask %s,", inet_ntoa(route_mask));
		//printf(" gw %s\n", inet_ntoa(route_gw));
	}

	fclose(net_route);
	return buffer;
} // get_default_gateway()

int get_ipv4_forward() {
	FILE *f = NULL;
	int mode = -1; // default error

	f = fopen(PROC_IPV4_IP_FORWARD, "r");
	if (f) {
		if (1 != fscanf(f, "%d", &mode)) mode = -1;
		fclose(f);
		return mode;
	}

	return mode;
} // get_ipv4_forward()

int prepare_forwarding(struct in_addr *remote_ptp_ip) {
	if (0 != run_command("%s -I FORWARD -i %s ! -o %s -j ACCEPT",
		iptables_bin, tc.tun_name, tc.tun_name)) return 1;

	if (0 != run_command("%s -I FORWARD -o %s ! -i %s -j ACCEPT",
		iptables_bin, tc.tun_name, tc.tun_name)) return 1;

	if (opt_invert_roles) {
		// client is router
		if (0 != run_command("%s -t nat -I POSTROUTING ! -o %s -j MASQUERADE",
			iptables_bin, tc.tun_name)) return 1;
	} else {
		if (0 != run_command("%s -t nat -I POSTROUTING -s %s -j MASQUERADE",
			iptables_bin, inet_ntoa(*remote_ptp_ip))) return 1;
	}

	if (ip_forward_state == 0) {
		if (0 != run_command("echo 1 > %s", PROC_IPV4_IP_FORWARD)) return 1;
	}

	return 0;
} // prepare_forwarding()

void clean_forwarding(struct in_addr *remote_ptp_ip) {
	run_command("%s -D FORWARD -i %s ! -o %s -j ACCEPT", iptables_bin, tc.tun_name, tc.tun_name);
	run_command("%s -D FORWARD -o %s ! -i %s -j ACCEPT", iptables_bin, tc.tun_name, tc.tun_name);

	if (opt_invert_roles) {
		run_command("%s -t nat -D POSTROUTING ! -o %s -j MASQUERADE", iptables_bin, tc.tun_name);
	} else {
		run_command("%s -t nat -D POSTROUTING -s %s -j MASQUERADE", iptables_bin, inet_ntoa(*remote_ptp_ip));
	}

	if (ip_forward_state == 0) {
		run_command("echo 0 > %s", PROC_IPV4_IP_FORWARD);
	}
} // clean_forwarding()

int main(int argc, char **argv) {
	int rc = 0;

	// Parse program options
	int opt = 0;
	while ( (opt = getopt(argc, argv, "hfscin:H:P:u:o:a:b:x:rw:t:")) != -1)
	switch (opt) {
		case 'h': print_help(argv[0]); break;

		case 'f': opt_foreground = 1; break;

		case 's': case 'c':
			if (work_mode != WORK_MODE_UNKNOWN) {
				fprintf(stderr,"You can't use several work mode in one process\n");
				return 1;
			} else {
				if (opt == 's')
					work_mode = WORK_MODE_SERVER;
				else
					work_mode = WORK_MODE_CLIENT;
			};
			break;

		case 'n':
			opt_ptp_subnet = optarg;
			if (!inet_pton(AF_INET, opt_ptp_subnet, &tun_ptp_subnet)) {
				fprintf(stderr,"Can't parse \"%s\" as point-to-point /30 subnet\n", optarg);
				return 1;
			};
			break;

		case 'i': opt_invert_roles = 1; break;
		case 'H': opt_ssh_host = optarg; break;
		case 'P': opt_ssh_port = atoi(optarg); break;
		case 'u': opt_ssh_user = optarg; break;
		case 'o': opt_ssh_password = optarg; break;
		case 'a': opt_ssh_pubkey = optarg; break;
		case 'b': opt_ssh_privkey = optarg; break;
		case 'x': opt_ssh_keypass = optarg; break;
		case 'r': opt_server_permanent = 1; break;

		case 'w':
			opt_server_retry_wait = atoi(optarg);
			if (opt_server_retry_wait < 0) {
				fprintf(stderr,"Value of -w parameter can't be negative\n");
				return 1;
			}
			break;

		case 't':
			if (!strcmp(optarg, "rfc1918")) {
				opt_client_route_rfc1918 = 1;
			} else if (!strcmp(optarg, "default")) {
				opt_client_route_default = 1;
			} else {
				if (!opt_client_routes) {
					opt_client_routes = strdup(optarg);
					if (opt_client_routes) opt_client_routes_count = 1;
				} else {
					size_t routes_len = strlen(opt_client_routes);
					size_t optarg_len = strlen(optarg);
					if (strchr(optarg,' ')) {
						fprintf(stderr, "Client route subnet \"%s\" can't contain space chars\n", optarg);
						return 1;
					}
					char *add_route = realloc(opt_client_routes, routes_len + optarg_len + 2);
					if (add_route) {
						*(add_route + routes_len) = ' ';
						memcpy(add_route + routes_len + 1, optarg, optarg_len + 1);
						opt_client_routes_count++;
						opt_client_routes = add_route;
					}
				}
			}
			break;

		case '?':
			fprintf(stderr,"Unknown option: %c\n", optopt);
			return 1;
			break;
	}; // switch

	// Check program configuration
	if (work_mode == WORK_MODE_UNKNOWN) {
		fprintf(stderr,"Unknown work mode!\n"
			"Use: \"%s -s\" for server mode\n"
			"\"%s -c\" for client mode\n", argv[0], argv[0]);
		return 1;
	} else if (work_mode == WORK_MODE_SERVER) {
		if (!opt_ssh_host) {
			fprintf(stderr,"SSH host and port (optionally) needed for server work mode!\n"
				"Use: \"%s -s ... -H <host> -P <port> ...\"", argv[0]);
			return 1;
		};
	};

	if (0 != geteuid()) {
		fprintf(stderr,"You can't run program under unprivileged user!\n"
			"Use: sudo %s\n", argv[0]);
		return 1;
	};

	if (!opt_ssh_user) {
		// TODO
		opt_ssh_user = "root";
	};

	if (!opt_ptp_subnet) {
		fprintf(stderr,"Unknown point-to-point network for tun iface\n"
			"Use: %s ... -n <subnet> ...\n"
			"<subnet> - is /30 network masked IP address\n", argv[0]);
		return 1;
	};

	for (const char **t = iptables_search; *t; t++) {
		if (0 == access(*t, R_OK | X_OK)) { iptables_bin = *t; break; }
	}
	if (!iptables_bin) {
		fprintf(stderr,"Can't found 'iptables' executable !\n");
		return 1;
	}

	for (const char **t = ip_search; *t; t++) {
		if (0 == access(*t, R_OK | X_OK)) { ip_bin = *t; break; }
	}
	if (!ip_bin) {
		fprintf(stderr,"Can't found 'ip' executable !\n");
		return 1;
	}

main_retry:
	// Init libssh2 library
	rc = libssh2_init(0);
	if (rc) {
		fprintf(stderr,"libssh2 init failed (%d)\n",rc);
		return 1;
	};

	// Prepare transfer buffers
	tun_buffer = calloc(1, tun_buffer_size);
	channel_buffer = calloc(1, channel_buffer_size);
	if (!tun_buffer || !channel_buffer) {
		fprintf(stderr,"Can't allocate memory for buffer\n");
		if (tun_buffer) free(tun_buffer);
		if (channel_buffer) free(channel_buffer);
		return 1;
	};

	// Prepare tun variables
	char tun_iface[IFNAMSIZ];
	int tun_number = 1;
	while (1) { // find empty name for tun device
		sprintf(tun_buffer, "/proc/sys/net/ipv4/conf/tun%d", tun_number);
		if (access(tun_buffer, F_OK) == -1) break;
		tun_number++;
	}; // while
	sprintf(tun_iface, "tun%d", tun_number);

	// Up tun iface
	if (-1 == up_tun_iface(&tc, tun_iface)) {
		fprintf(stderr,"Can't create tun iface: %s\n", tun_iface);
		if (tun_buffer) free(tun_buffer);
		if (channel_buffer) free(channel_buffer);
		return 1;
	};
	if (0 != run_command("%s link set %s up", ip_bin, tc.tun_name)) {
		fprintf(stderr, "error up tun iface\n");
		goto exit_tun;
	};

	// Save system IPv4 forward mode
	ip_forward_state = get_ipv4_forward();

	// Set IP for local tun iface
	struct in_addr local_ptp_ip = tun_ptp_subnet;
	struct in_addr remote_ptp_ip = tun_ptp_subnet;
	if (work_mode == WORK_MODE_SERVER) {
		local_ptp_ip.s_addr += ntohl(1);
		remote_ptp_ip.s_addr += ntohl(2);
	} else {
		local_ptp_ip.s_addr += ntohl(2);
		remote_ptp_ip.s_addr += ntohl(1);
	};
	if (0 != run_command("%s address add %s/30 dev %s", ip_bin,
		inet_ntoa(local_ptp_ip), tc.tun_name)
	) {
		fprintf(stderr, "error set ip address on tun iface\n");
		goto exit_tun_link;
	};

	if (work_mode == WORK_MODE_CLIENT) {
		// If we want change default gw, we must save current route to SSH connected client
		if (opt_client_route_default == 1) {
			const char *ssh_remote_addr = getenv("SSH_CLIENT");
			if (!ssh_remote_addr) {
				fprintf(stderr, "can't found %s in environment\n","SSH_CLIENT");
				goto exit_tun_ip;
			}

			char gw_ip[128];
			char remote_ssh_ip[128];
			if (
				1 == sscanf(ssh_remote_addr, "%s", remote_ssh_ip)
				&& get_default_gateway(gw_ip)
				&& strlen(gw_ip) > 0
				&& -1 != asprintf(&client_default_route_delete_command,"%s route del %s via %s", ip_bin, remote_ssh_ip, gw_ip)
			) {
				if (
					0 != run_command("%s route add %s via %s", ip_bin, remote_ssh_ip, gw_ip)
				) {
					fprintf(stderr, "error set route to %s via %s gateway\n", remote_ssh_ip, gw_ip);
					goto exit_tun_ip;
				}

				if (0 != run_command("%s route add %s via %s", ip_bin,
					"0/0", inet_ntoa(remote_ptp_ip))
				) {
					fprintf(stderr, "error set default route via tun iface\n");
					goto exit_client_default_gw;
				}
			} else {
				fprintf(stderr, "error get info about default route\n");
				goto exit_tun_ip;
			}
		}

		// Add RFC1918 private subnets via tun connection
		if (opt_client_route_rfc1918 == 1) {
			const char *rfc1918[] = {"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",NULL};
			const char **net = rfc1918;
			while (*net) {
				if (0 != run_command("%s route add %s via %s", ip_bin,
					*net, inet_ntoa(remote_ptp_ip))
				) {
					fprintf(stderr, "error set route for %s via tun iface\n", *net);
					if (client_default_route_delete_command) goto exit_client_default_gw;
					goto exit_tun_ip;
				};
				net++;
			}
		}

		// Add additional subnets routes via tun connection
		if (opt_client_routes_count > 0) {
			char subnet[128];
			char *scp = opt_client_routes;
			while (1 == sscanf(scp, "%s", subnet)) {
				if (0 != run_command("%s route add %s via %s", ip_bin,
					subnet, inet_ntoa(remote_ptp_ip))
				) {
					fprintf(stderr, "error set route for %s via tun iface\n", subnet);
					if (client_default_route_delete_command) goto exit_client_default_gw;
					goto exit_tun_ip;
				}
				scp += strlen(subnet);
				if (*scp == ' ') scp++; else break;
			}
		}

		// Prepare firewall for forwarding traffic
		if (opt_invert_roles && prepare_forwarding(&remote_ptp_ip) != 0) goto exit_client_default_gw;

		goto skip_server_ssh;
	}

	fprintf(stderr,"Work in server mode\n");

	char *progname = strrchr(argv[0], '/');
	if (-1 == asprintf(&vpncmd,"%s%s -c %s-n %s",
		(strcmp(opt_ssh_user,"root") ? "sudo -E " : ""),
		progname ? progname+1 : argv[0],
		opt_invert_roles ? "-i ": "",
		opt_ptp_subnet))
	{
		fprintf(stderr, "Can't create ssh run command\n");
		goto exit_tun_ip;
	}

	// Add routes options in client command line
	char *vpncmdadd = NULL;
	size_t vpncmdlen = strlen(vpncmd);
	if (opt_client_route_default == 1) {
		vpncmdadd = realloc(vpncmd, vpncmdlen + strlen(" -t ") + strlen("default") + 1);
		if (vpncmdadd) {
			vpncmdlen += sprintf(vpncmdadd + vpncmdlen, " -t %s", "default");
			vpncmd = vpncmdadd;
		}
	}
	if (opt_client_route_rfc1918 == 1) {
		vpncmdadd = realloc(vpncmd, vpncmdlen + strlen(" -t ") + strlen("rfc1918") + 1);
		if (vpncmdadd) {
			vpncmdlen += sprintf(vpncmdadd + vpncmdlen, " -t %s", "rfc1918");
			vpncmd = vpncmdadd;
		}
	}
	if (opt_client_routes_count > 0) {
		char subnet[128];
		char *scp = opt_client_routes;
		while (1 == sscanf(scp, "%s", subnet)) {
			vpncmdadd = realloc(vpncmd, vpncmdlen + strlen(" -t ") + strlen(subnet) + 1);
			if (vpncmdadd) {
				vpncmdlen += sprintf(vpncmdadd + vpncmdlen, " -t %s", subnet);
				vpncmd = vpncmdadd;
			}
			scp += strlen(subnet);
			if (*scp == ' ') scp++; else break;
		}
	}

	if (opt_ssh_user) sshconn.user = strdup(opt_ssh_user);
	if (opt_ssh_password) sshconn.password = strdup(opt_ssh_password);
	if (opt_ssh_host) sshconn.server_ip = strdup(opt_ssh_host);
	sshconn.port = opt_ssh_port;
	if (opt_ssh_pubkey) sshconn.pubkey = strdup(opt_ssh_pubkey);
	if (opt_ssh_privkey) sshconn.privkey = strdup(opt_ssh_privkey);
	if (opt_ssh_keypass) sshconn.keypass = strdup(opt_ssh_keypass);

	if (0 != up_ssh_session(&sshconn)) {
		fprintf(stderr,"error create ssh session\n");
		clean_ssh_session(&sshconn);
		goto exit_tun_ip;
	}

	if (0 != up_ssh_channel(&sshconn)) goto exit_ssh;

	fprintf(stderr,"Try run SSH: %s\n", vpncmd);
	while (( rc = libssh2_channel_exec(sshconn.channel, vpncmd)) == LIBSSH2_ERROR_EAGAIN) {
		if (-1 == ssh_waitsocket(sshconn.sock, sshconn.session)) break;
	}
	if (rc) {
		fprintf(stderr,"SSH exec error: %d\n", rc);
		goto exit_channel;
	}

	// Read client output and try find start signature
	ssize_t nread;
	int find_client_sign = 0;
	const char *sign_pos = session_start_sign;

	do {
		nread = libssh2_channel_read(sshconn.channel,
			channel_buffer, channel_buffer_size);

		if (nread > 0) { // try find start signature in buffer
			ssize_t n = 0;
			while (!find_client_sign && n < nread) {
				if (*sign_pos == (unsigned char)channel_buffer[n]) {
					sign_pos++;
				} else {
					sign_pos = session_start_sign;
				}
				n++;
				if (*sign_pos == '\0') {
					find_client_sign = 1;
					break;
				}
			}
		} else {
			if (nread == LIBSSH2_ERROR_EAGAIN) {
				if (-1 == ssh_waitsocket(sshconn.sock, sshconn.session)) break;
				continue;
			} else if (nread < 0) break;
		}
		if (find_client_sign) break;

		if (libssh2_channel_eof(sshconn.channel)) goto exit_channel;
	} while (!find_client_sign);

	if (!find_client_sign) {
		fprintf(stderr,"Can't find start channel signature\n");
		goto exit_channel;
	}

	// Prepare firewall for forwarding traffic
	if (!opt_invert_roles && prepare_forwarding(&remote_ptp_ip) != 0) goto exit_iptables;

	if (!opt_foreground) {
		if (daemon(0, 0) != 0) {
			fprintf(stderr,"Can't daemonize process!\n");
			goto exit_iptables;
		};
	} else {
		fprintf(stderr,"Work in foreground mode (press Ctrl+C for break)\n");
	}

skip_server_ssh:
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	program_state = 1; // start

	// Main work cycle
	if (work_mode == WORK_MODE_CLIENT) {
		rc = client_work(&tc);
		if (rc < 0) {
			syslog(LOG_ERR,"%s() end work with code %d", "client_work", rc);
		}
		goto exit_client_default_gw;
	} else {
		rc = server_work(&tc, &sshconn);
		if (rc < 0) {
			syslog(LOG_ERR,"%s() end work with code %d", "server_work", rc);
		}
	}

exit_iptables:
	if (!opt_invert_roles) clean_forwarding(&remote_ptp_ip);

exit_channel:
	clean_ssh_channel(&sshconn);
exit_ssh:
	clean_ssh_session(&sshconn);

exit_client_default_gw:
	if (work_mode == WORK_MODE_CLIENT) {
		if (opt_invert_roles) clean_forwarding(&remote_ptp_ip);

		if (client_default_route_delete_command) {
			run_command("%s", client_default_route_delete_command);
			free(client_default_route_delete_command);
		}
	}
exit_tun_ip:
	run_command("%s address del %s/30 dev %s", ip_bin,
		inet_ntoa(local_ptp_ip), tc.tun_name);
exit_tun_link:
	run_command("%s link set %s down", ip_bin, tc.tun_name);
exit_tun:
	if (tun_buffer) { free(tun_buffer); tun_buffer = NULL; }
	if (channel_buffer) { free(channel_buffer); channel_buffer = NULL; }
	if (vpncmd) { free(vpncmd); vpncmd = NULL; }
	down_tun_iface(&tc);

	libssh2_exit();

	if (
		work_mode == WORK_MODE_SERVER
		&& opt_server_permanent
		&& program_state != 3
	) {
		// TODO refactor permanent mode, restart only SSH session
		// and don't touch tun and ip/route/iptables
		if (opt_server_retry_wait > 0) sleep(opt_server_retry_wait);
		goto main_retry;
	}

	if (opt_client_routes) { free(opt_client_routes); opt_client_routes = NULL; }
	return 0;
} // main()
