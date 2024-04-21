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
#include <pthread.h>

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

	if (!conn || !name) return -1;

	if ((conn->tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
		fprintf(stderr,"Can't open /dev/net/tun: %s\n", strerror(errno));
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
//////// TIMEOUT READ/WRITE
///////////////////////////////////////////////////////
ssize_t timeoutread(int t, int fd, char *buf, size_t len)
{
	fd_set rfds;
	struct timeval tv;
	tv.tv_sec = t;
	tv.tv_usec = 100000;
	FD_ZERO(&rfds);
	FD_SET(fd,&rfds);
	if (select(fd + 1, &rfds, NULL, NULL, &tv) == -1) return -1;
	if (FD_ISSET(fd, &rfds))
		return read(fd, buf, len);
	errno = 0;
	return 0;
} // timeoutread()

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
//	libssh2_keepalive_config(sess->session, 1, 15);

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
//		// TODO
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
		goto defer;
	} else if (comret != 0) {
		fprintf(stderr, "Command \"%s\" return not zero code %d\n", com, comret);
		goto defer;
	}
	ret = comret;
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

int opt_server_permanent = 0;

const char *session_start_sign = "ReAdy-SeT-Go!\n";
struct tun_connection tc = {0};
struct ssh_session sshconn = {0};

char *tun_buffer = NULL;
size_t tun_buffer_size = 32 << 10;
char *channel_buffer = NULL;
size_t channel_buffer_size = 32 << 10;

///////////////////////////////////////////////////////
//////// THREADS
///////////////////////////////////////////////////////
pthread_t pth[2] = {0};

void *thread_client_read_tun(void *data) {
	ssize_t n;
	size_t packet_size;
	size_t pos;

	while (program_state == 0) {};

	// send SIGN to server detect session start
	printf("%s", session_start_sign);
	fflush(stdout);

	while (program_state == 1) {
		n = timeoutread(1, tc.tun_fd, tun_buffer + sizeof(packet_size),
			tun_buffer_size - sizeof(packet_size));
		if (n == 0) continue;
		if (n < 0) { program_state = 2; break; }

		pos = htonl(n);
		memcpy(tun_buffer, &pos, sizeof(size_t));

		packet_size = n + sizeof(pos);

//		pos = fwrite(tun_buffer, 1, packet_size, stdout);
//		if (pos < packet_size) { program_state = 2; break; }
//		fflush(stdout);

		pos = 0;
		do {
			if (program_state != 1) break;
			if ((n = write(STDOUT_FILENO, tun_buffer + pos, packet_size - pos)) < 0) {
				if ( errno == EINTR || errno == EAGAIN ) continue;
				break;
			};
			pos += n;
		} while (packet_size - pos > 0);
		if (n < 0) { program_state = 2; break; }
	} // while

	pthread_exit(NULL);
} // thread_client_read_tun()

void *thread_client_read_ssh(void *data) {
	ssize_t n;
	size_t packet_size;
	size_t pos;

	while (program_state == 0) {};
	while (program_state == 1) {
		n = timeoutread(1, STDIN_FILENO,
			(char *)&packet_size, sizeof(packet_size));
		if (n == 0) continue;
		if (n < 0) { program_state = 2; break; }

		packet_size = ntohl(packet_size);

		if (packet_size > channel_buffer_size) {
			char *r = realloc(channel_buffer, packet_size);
			if (!r) { program_state = 2; break; }
			channel_buffer = r;
			channel_buffer_size = packet_size;
		}

		pos = 0;
		do {
			if (program_state != 1) break;
			n = timeoutread(1, STDIN_FILENO,
				channel_buffer + pos, packet_size - pos);
			if (n == 0) continue;
			else if (n < 0) { program_state = 2; break; }
			pos += n;
		} while (packet_size - pos > 0);
		if (n < 0) { program_state = 2; break; }

		do {
			if (program_state != 1) break;
			if ((n = write(tc.tun_fd, channel_buffer, packet_size)) < 0) {
				if ( errno == EINTR || errno == EAGAIN ) continue;
				break;
			} else break;
		} while (1);
		if (n < 0) { program_state = 2; break; }
	} // while

	pthread_exit(NULL);
} // thread_client_read_ssh()

void *thread_server_read_tun(void *data) {
	ssize_t n;
	size_t packet_size;
	size_t pos;

	while (program_state == 0) {};
	while (program_state == 1) {
		n = timeoutread(1, tc.tun_fd, tun_buffer + sizeof(packet_size),
			tun_buffer_size - sizeof(packet_size));
		if (n == 0) continue;
		if (n < 0) { program_state = 2; break; }

		pos = htonl(n);
		memcpy(tun_buffer, &pos, sizeof(size_t));

		packet_size = n + sizeof(pos);
		pos = 0;
		do {
			if (program_state != 1) break;
			n = libssh2_channel_write(sshconn.channel,
				tun_buffer + pos, packet_size - pos);
			if (n == LIBSSH2_ERROR_EAGAIN) {
				if (-1 == ssh_waitsocket(sshconn.sock, sshconn.session)) break;
				continue;
			} else if (n < 0) break;
			pos += n;
		} while (packet_size - pos > 0);
		if (n < 0) { program_state = 2; break; }
	} // while

	pthread_exit(NULL);
} // thread_server_read_tun()

void *thread_server_read_ssh(void *data) {
	ssize_t n;
	size_t packet_size;
	size_t pos;

	while (program_state == 0) {};

	while (program_state == 1) {
		pos = 0;
		do {
			if (program_state != 1) break;
			n = libssh2_channel_read(sshconn.channel,
				(char *)(&packet_size + pos), sizeof(packet_size) - pos);
			if (n == LIBSSH2_ERROR_EAGAIN) {
				if (-1 == ssh_waitsocket(sshconn.sock, sshconn.session)) break;
				continue;
			} else if (n < 0) break;
			pos += n;
		} while (sizeof(packet_size) - pos > 0);
		if (n < 0) { program_state = 2; break; }
		if (program_state != 1) break;

		packet_size = ntohl(packet_size);
		if (packet_size > channel_buffer_size) {
			char *r = realloc(channel_buffer, packet_size);
			if (!r) { program_state = 2; break; }
			channel_buffer = r;
			channel_buffer_size = packet_size;
		}

		pos = 0;
		do {
			if (program_state != 1) break;
			n = libssh2_channel_read(sshconn.channel,
				channel_buffer + pos, packet_size - pos);
			if (n == LIBSSH2_ERROR_EAGAIN) {
				if (-1 == ssh_waitsocket(sshconn.sock, sshconn.session)) break;
				continue;
			} else if (n < 0) break;
			pos += n;
		} while (packet_size - pos > 0);
		if (n < 0) { program_state = 2; break; }
		if (program_state != 1) break;

		do {
			if (program_state != 1) break;
			n = write(tc.tun_fd, channel_buffer, packet_size);
			if (n < 0) {
				if ( errno == EINTR || errno == EAGAIN ) continue;
				break;
			} else break;
		} while(1);
		if (n < 0) { program_state = 2; break; }
	} // while

	pthread_exit(NULL);
} // thread_server_read_ssh()

void print_help(const char *prog) {
	printf("%s tun based VPN via SSH connection\n", prog);
	printf("Usage: %s [options]\n", prog);
	printf("\t-s - work as server (connect to remote ssh)\n");
	printf("\t-c - work as client\n");
	printf("\t-n <subnet> - tun p-t-p /30 subnet (example: 10.254.254.0)\n");
	printf("\t-H <ip> - ssh host (example: 181.67.121.32)\n");
	printf("\t-P <port> - ssh port (default 22)\n");
	printf("\t-u <user> - ssh user (default root)\n");
	printf("\t-o <password> - password for ssh auth\n");
	printf("\t-a <id_rsa.pub> - public key file\n");
	printf("\t-b <id_rsa> - private key file\n");
	printf("\t-x <password> - private key password\n");
//	printf("\t-r - permanent connection\n");
	exit(0);
} // print_help()

int main(int argc, char **argv) {
	int rc = 0;

	// Parse program options
	int opt = 0;
	while ( (opt = getopt(argc, argv, "hscn:H:P:u:o:a:b:x:r")) != -1)
	switch (opt) {
		case 'h': print_help(argv[0]); break;

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

		case 'H': opt_ssh_host = optarg; break;
		case 'P': opt_ssh_port = atoi(optarg); break;
		case 'u': opt_ssh_user = optarg; break;
		case 'o': opt_ssh_password = optarg; break;
		case 'a': opt_ssh_pubkey = optarg; break;
		case 'b': opt_ssh_privkey = optarg; break;
		case 'x': opt_ssh_keypass = optarg; break;
		case 'r': opt_server_permanent = 1; break;

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

//main_retry:
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
	if (0 != run_command("/sbin/ip link set %s up", tc.tun_name)) {
		fprintf(stderr, "error up tun iface\n");
		goto exit_tun;
	};

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
	if (0 != run_command("/sbin/ip address add %s/30 dev %s",
		inet_ntoa(local_ptp_ip), tc.tun_name)
	) {
		fprintf(stderr, "error set ip address on tun iface\n");
		goto exit_tun_link;
	};

	if (work_mode == WORK_MODE_CLIENT) {
		const char *rfc1918[] = {"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",NULL};
		const char **net = rfc1918;
		while (*net) {
			if (0 != run_command("/sbin/ip route add %s via %s",
				*net, inet_ntoa(remote_ptp_ip))
			) {
				fprintf(stderr, "error set route for %s tun iface\n", *net);
				goto exit_tun_link;
			};
			net++;
		}
		goto skip_server_ssh;
	}

	fprintf(stderr,"Work in server mode\n");

	char *vpncmd = NULL;
	char *progname = strrchr(argv[0], '/');
	if (-1 == asprintf(&vpncmd,"sudo %s -c -n %s", progname ? progname+1 : argv[0], opt_ptp_subnet)) {
		fprintf(stderr, "Can't create ssh run command\n");
		goto exit_tun_ip;
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
	while(1) {
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
			}
			if (find_client_sign) break;
		} while (nread > 0);
		if (nread == LIBSSH2_ERROR_EAGAIN) {
			ssh_waitsocket(sshconn.sock, sshconn.session);
			continue;
		} else break;
	};

	if (!find_client_sign) {
		fprintf(stderr,"Can't find start channel signature\n");
		goto exit_channel;
	}

	if (0 != run_command("/usr/sbin/iptables -I FORWARD -i %s ! -o %s -j ACCEPT",tc.tun_name,tc.tun_name)) goto exit_iptables;
	if (0 != run_command("/usr/sbin/iptables -I FORWARD -o %s ! -i %s -j ACCEPT",tc.tun_name,tc.tun_name)) goto exit_iptables;
	if (0 != run_command("/usr/sbin/iptables -t nat -I POSTROUTING -s %s -j MASQUERADE",inet_ntoa(remote_ptp_ip))) goto exit_iptables;
	if (0 != run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")) goto exit_iptables;

#ifdef PRODUCTION
	if (daemon(0, 0) != 0) {
		fprintf(stderr,"Can't daemonize process!\n");
		goto exit_iptables;
	};
#endif

	rc = pthread_create(&pth[0], NULL, thread_server_read_ssh, NULL);
	if (rc != 0) {
		fprintf(stderr,"Can't start ssh thread\n");
		goto exit_threads;
	};

	rc = pthread_create(&pth[1], NULL, thread_server_read_tun, NULL);
	if (rc != 0) {
		fprintf(stderr,"Can't start tun thread\n");
		program_state = 2;
		goto exit_threads;
	};

	goto skip_client_ssh;

skip_server_ssh:
	rc = pthread_create(&pth[0], NULL, thread_client_read_ssh, NULL);
	if (rc != 0) {
		fprintf(stderr,"Can't start ssh thread\n");
		goto exit_threads;
	};
	rc = pthread_create(&pth[1], NULL, thread_client_read_tun, NULL);
	if (rc != 0) {
		fprintf(stderr,"Can't start tun thread\n");
		program_state = 2;
		goto exit_threads;
	};

skip_client_ssh:
	program_state = 1; // start pthreads work

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// Main work cycle
	while (program_state == 1) sleep(1);

exit_threads:
	if (pth[0] != 0) pthread_join(pth[0], NULL);
	if (pth[1] != 0) pthread_join(pth[1], NULL);

	if (work_mode == WORK_MODE_CLIENT) goto exit_tun_ip;

exit_iptables:
	run_command("/usr/sbin/iptables -D FORWARD -i %s ! -o %s -j ACCEPT",tc.tun_name,tc.tun_name);
	run_command("/usr/sbin/iptables -D FORWARD -o %s ! -i %s -j ACCEPT",tc.tun_name,tc.tun_name);
	run_command("/usr/sbin/iptables -t nat -D POSTROUTING -s %s -j MASQUERADE",inet_ntoa(remote_ptp_ip));
	//run_command("/usr/sbin/iptables -t nat -D POSTROUTING -i %s -j MASQUERADE",tc.tun_name);
	run_command("echo 0 > /proc/sys/net/ipv4/ip_forward");

exit_channel:
	clean_ssh_channel(&sshconn);
exit_ssh:
	clean_ssh_session(&sshconn);
exit_tun_ip:
	run_command("/sbin/ip address del %s/30 dev %s",
		inet_ntoa(local_ptp_ip), tc.tun_name);
exit_tun_link:
	run_command("/sbin/ip link set %s down", tc.tun_name);
exit_tun:
	if (tun_buffer) { free(tun_buffer); tun_buffer = NULL; }
	if (channel_buffer) { free(channel_buffer); channel_buffer = NULL; }
	down_tun_iface(&tc);

	libssh2_exit();

//	if (opt_server_permanent && program_state == 2) goto main_retry;
	return 0;
} // main()
