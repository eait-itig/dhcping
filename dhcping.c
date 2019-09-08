
/*
 * Copyright (c) 2019 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>

#include "dhcp.h"

#define DHCP_USER "_dhcp"
#define DHCP_PORT "bootps"

/* number of packets to try sending */
#define DHCP_TRIES_MIN		1
#define DHCP_TRIES_MAX		32
#define DHCP_TRIES_DEFAULT	3

/* how long between packet sends */
#define DHCP_IVAL_MIN		1
#define DHCP_IVAL_MAX		10
#define DHCP_IVAL_DEFAULT	2

/* maximum wait time */
#define DHCP_MAXWAIT_MIN	3
#define DHCP_MAXWAIT_MAX	60
#define DHCP_MAXWAIT_DEFAULT	8

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-i interval] [-t tries] [-w wait]"
	    " -h mac -s server\n", __progname);

	exit(1);
}

struct dhcping {
	uint8_t			packet[BOOTP_MIN_LEN];

	int			s;
	struct timeval		interval;
	unsigned int		retries;
	unsigned short		secs;

	struct event		input;
	struct event		retry;
	struct event		maxwait;

	unsigned int		verbose;
};

static void	dhcping_packet_init(struct dhcping *, int,
		    const struct ether_addr *);

static void	dhcping_maxwait(int, short, void *);
static void	dhcping_retry(int, short, void *);
static void	dhcping_input(int, short, void *);

static struct dhcp_packet *
dhcping_packet(struct dhcping *dhcping)
{
	return ((struct dhcp_packet *)dhcping->packet);
}

static int
dhcping_bind_connect(int s, const struct addrinfo *lres, const char *remote,
    const char **errstr)
{
	struct addrinfo *res, *res0;
	int serrno;
	int error;
	struct addrinfo hints = {
		.ai_family = lres->ai_family,
		.ai_socktype = lres->ai_socktype,
		.ai_protocol = lres->ai_protocol,
	};

	*errstr = NULL;

	error = getaddrinfo(remote, DHCP_PORT, &hints, &res0);
	if (error != 0) {
		*errstr = gai_strerror(error);
		return (-1);
	}

	error = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			serrno = errno;
			continue;
		}

		error = 0;
		break;
	}

	if (error == -1)
		*errstr = strerror(serrno);

	freeaddrinfo(res0);
	return (error);
}

static int
dhcping_connect(const char *local, const char *remote)
{
	struct addrinfo *res, *res0;
	int serrno;
	int error;
	int s;
	const char *cause;
	const char *errstr = NULL;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_PASSIVE,
	};

	error = getaddrinfo(local, DHCP_PORT, &hints, &res0);
	if (error) {
		errx(1, "local address %s: %s", (local == NULL) ? "*" : local,
		    gai_strerror(error));
	}

	for (res = res0; res != NULL; res = res->ai_next) {
		errstr = NULL;

		s = socket(res->ai_family, res->ai_socktype | SOCK_NONBLOCK,
		    res->ai_protocol);
		if (s == -1) {
			serrno = errno;
			cause = "socket";
			continue;
		}

		if (bind(s, res->ai_addr, res->ai_addrlen) == -1) {
			serrno = errno;
			cause = "bind";
			close(s);
			s = -1;
			continue;
		}

		if (dhcping_bind_connect(s, res, remote, &errstr) == -1) {
			close(s);
			s = -1;
			continue;
		}

		break;  /* okay we got one */
	}

	if (errstr != NULL)
		errx(1, "server %s: %s", remote, errstr);
	else if (s == -1) {
		errc(1, serrno, "local address %s port %s %s",
		    (local == NULL) ? "*" : local, DHCP_PORT, cause);
	}

	freeaddrinfo(res0);

	return (s);
}

int
main(int argc, char *argv[])
{
	struct dhcping dhcping = {
		.verbose = 0,
		.interval = { .tv_sec = DHCP_IVAL_DEFAULT },
		.retries = DHCP_TRIES_DEFAULT,
	};
	struct timeval maxwait = { .tv_sec = DHCP_MAXWAIT_DEFAULT };
	const struct ether_addr *ea;
	const char *mac = NULL;
	const char *self = NULL;
	const char *server = NULL;
	const char *user = DHCP_USER;
	const char *errstr;
	int ch;

	while ((ch = getopt(argc, argv, "h:l:s:t:u:w:v")) != -1) {
		switch (ch) {
		case 'h':
			mac = optarg;
			break;
		case 'i': /* interval between tries */
			dhcping.interval.tv_sec = strtonum(optarg,
			    DHCP_IVAL_MIN, DHCP_IVAL_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "interval %s s: %s", optarg, errstr);
			break;
		case 'l':
			self = optarg;
			break;
		case 't': /* number of tries */
			dhcping.retries = strtonum(optarg,
			    DHCP_TRIES_MIN, DHCP_TRIES_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "tries %s: %s", optarg, errstr);
			break;
		case 's':
			server = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		case 'w': /* maximum wait time */
			maxwait.tv_sec = strtonum(optarg,
			    DHCP_MAXWAIT_MIN, DHCP_MAXWAIT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "wait %s s: %s", optarg, errstr);
			break;
		case 'v':
			dhcping.verbose = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0 || mac == NULL || server == NULL) {
		usage();
	}

	if (dhcping.retries * dhcping.interval.tv_sec > maxwait.tv_sec) {
		errx(1, "tries %u by interval %lld s > wait %lld s",
		    dhcping.retries, dhcping.interval.tv_sec, maxwait.tv_sec);
	}

	ea = ether_aton(mac);
	if (ea == NULL)
		errx(1, "invalid mac %s", mac);

	dhcping.s = dhcping_connect(self, server);
	/* error printed by dhcping_connect */

	dhcping_packet_init(&dhcping, dhcping.s, ea);

	event_init();

	event_set(&dhcping.input, dhcping.s, EV_READ|EV_PERSIST,
	    dhcping_input, &dhcping);

	evtimer_set(&dhcping.maxwait, dhcping_maxwait, &dhcping);
	evtimer_set(&dhcping.retry, dhcping_retry, &dhcping);

	event_add(&dhcping.input, NULL);
	evtimer_add(&dhcping.maxwait, &maxwait);
	dhcping_retry(0, EV_TIMEOUT, &dhcping);

	event_dispatch();

	return (0);
}

static const uint8_t dhcping_requested[] = {
	DHO_SUBNET_MASK,
	DHO_BROADCAST_ADDRESS,
	DHO_TIME_OFFSET,
	DHO_CLASSLESS_STATIC_ROUTES,
	DHO_ROUTERS,
	DHO_DOMAIN_NAME,
	DHO_DOMAIN_SEARCH,
	DHO_DOMAIN_NAME_SERVERS,
	DHO_HOST_NAME,
	DHO_BOOTFILE_NAME,
	DHO_TFTP_SERVER,
};

static void
dhcping_packet_init(struct dhcping *dhcping, int s, const struct ether_addr *ea)
{
	static const uint8_t cookie[DHCP_OPTIONS_COOKIE_LEN] =
	    DHCP_OPTIONS_COOKIE;
	struct dhcp_packet *p = dhcping_packet(dhcping);
	struct sockaddr_in sin;
	socklen_t sinlen = sizeof(sin);
	uint8_t *dho;

	if (getsockname(s, (struct sockaddr *)&sin, &sinlen) == -1)
		err(1, "getsockname");
	if (sin.sin_family != AF_INET)
		errx(1, "unexpected sockname af %d", sin.sin_family);

	p->op = BOOTREQUEST;
	p->htype = HTYPE_ETHER;
	p->hlen = sizeof(*ea);
	p->hops = 1;
	p->xid = htonl(getpid());
	p->secs = 0;
	p->flags = 0;
	p->giaddr = sin.sin_addr;
	memcpy(p->chaddr, ea, sizeof(*ea));
	memcpy(p->cookie, cookie, sizeof(cookie));

	dho = (uint8_t *)(p + 1);

	*dho++ = DHO_DHCP_MESSAGE_TYPE;
	*dho++ = 1;
	*dho++ = DHCPDISCOVER;

	*dho++ = DHO_DHCP_PARAMETER_REQUEST_LIST;
	*dho++ = sizeof(dhcping_requested);
	memcpy(dho, dhcping_requested, sizeof(dhcping_requested));
	dho += sizeof(dhcping_requested);

	*dho++ = DHO_END;
}

static void
dhcping_input(int s, short revents, void *arg)
{
	struct dhcp_packet reply;
	ssize_t rv;

	rv = read(s, &reply, sizeof(reply));
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			return; /* try again later */
		default:
			break;
		}
		err(1, "input");
	}

	exit(0);
}

static void
dhcping_retry(int thing, short revents, void *arg)
{
	struct dhcping *dhcping = arg;
	struct dhcp_packet *p = dhcping_packet(dhcping);
	ssize_t rv;

	p->secs = htons(dhcping->secs);

retry:
	rv = write(dhcping->s, dhcping->packet, sizeof(dhcping->packet));
	if (rv == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
			goto retry;
		default:
			break;
		}

		err(1, "transmit");
	}

	if (--dhcping->retries == 0)
		return;

	dhcping->secs += dhcping->interval.tv_sec;
	evtimer_add(&dhcping->retry, &dhcping->interval);
}

static void
dhcping_maxwait(int fd, short revents, void *arg)
{
	struct dhcping *dhcping = arg;

	if (dhcping->verbose)
		warnx("timeout waiting for reply");

	exit(2);
}
