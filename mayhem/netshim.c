/* A loopback address private to each fuzzer process, for the GigE Vision harnesses.
 *
 * GVCP always uses UDP port 3956, and ArvGvFakeCamera listens only on a network interface's own
 * address. On a stock host "lo" has just 127.0.0.1, so two fuzzer processes in one network
 * namespace (two Mayhem workers, or gvsp_stream next to gvcp_fakecamera) would share
 * 127.0.0.1:3956: one camera fails to bind, and its process's GVCP traffic goes to the other
 * process's camera, so results stop depending on the input alone.
 *
 * Every harness is linked with -Wl,--wrap=getifaddrs. __wrap_getifaddrs returns the real list
 * with each IPv4 127.0.0.1 (the "lo" address, and its broadcast/destination address when the
 * kernel reports one) replaced in place by fuzz_loopback_address(), a random 127.x.y.z (all of
 * 127/8 is loopback on Linux). Nothing else in the list changes, and the aravis code that reads
 * it (arvnetwork.c) runs unmodified. The harnesses then bind, connect and create cameras/devices
 * on that address.
 *
 * The address is random, not derived from getpid(): Mayhem workers run in their own PID
 * namespaces, so their fuzzer processes have the same small PIDs, and workers that share a
 * network namespace would all pick the same address. A harness that finds the GVCP port of its
 * address taken calls fuzz_loopback_repick() and tries again with a new random address. */
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int __real_getifaddrs (struct ifaddrs **ifap);

static uint32_t host = 0;	/* the address, host byte order; 0 until first picked */

/* A random 127.x.y.z with x in 1..254 and z in 1..254 (never 127.0.0.0/16, never a .0/.255). */
void
fuzz_loopback_repick (void)
{
	uint32_t r = 0;
	struct timespec ts;

	if (getrandom (&r, sizeof (r), GRND_NONBLOCK) != (ssize_t) sizeof (r)) {
		clock_gettime (CLOCK_MONOTONIC, &ts);
		r = (uint32_t) ts.tv_nsec * 2654435761u ^ (uint32_t) getpid () ^ (uint32_t) ts.tv_sec;
	}
	host = (127u << 24) | ((1u + (r & 0xffff) % 254u) << 16) | (((r >> 16) & 0xff) << 8) |
	       (1u + ((r >> 24) % 254u));
}

/* The process's private loopback address, as an IPv4 address in network byte order. */
struct in_addr
fuzz_loopback_address (void)
{
	struct in_addr in;

	if (host == 0)
		fuzz_loopback_repick ();
	in.s_addr = htonl (host);
	return in;
}

/* The same, as a dotted string in a static buffer. */
const char *
fuzz_loopback_address_string (void)
{
	static char text[INET_ADDRSTRLEN];
	struct in_addr in = fuzz_loopback_address ();

	inet_ntop (AF_INET, &in, text, sizeof (text));
	return text;
}

static void
rewrite (struct sockaddr *sa)
{
	struct sockaddr_in *in = (struct sockaddr_in *) sa;

	if (sa != NULL && sa->sa_family == AF_INET && in->sin_addr.s_addr == htonl (INADDR_LOOPBACK))
		in->sin_addr = fuzz_loopback_address ();
}

int
__wrap_getifaddrs (struct ifaddrs **ifap)
{
	struct ifaddrs *iter;
	int ret = __real_getifaddrs (ifap);

	if (ret == 0) {
		for (iter = *ifap; iter != NULL; iter = iter->ifa_next) {
			rewrite (iter->ifa_addr);
			rewrite (iter->ifa_broadaddr);
		}
	}
	return ret;
}

/* Is UDP port `port` of the process's address free right now? (A bind without SO_REUSEADDR.) */
int
fuzz_loopback_port_free (unsigned short port)
{
	struct sockaddr_in addr = {0};
	int fd = socket (AF_INET, SOCK_DGRAM, 0);
	int ok;

	if (fd < 0)
		return 1;	/* can't tell; let the caller go on */
	addr.sin_family = AF_INET;
	addr.sin_port = htons (port);
	addr.sin_addr = fuzz_loopback_address ();
	ok = bind (fd, (struct sockaddr *) &addr, sizeof (addr)) == 0;
	close (fd);
	return ok;
}
