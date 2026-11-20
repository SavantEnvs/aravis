/* Fuzz the GigE Vision control protocol (GVCP) client: ArvGvDevice (arvgvdevice.c
 * _send_cmd_and_receive_ack and the ack accessors in arvgvcpprivate.h, bootstrap register
 * parsing, GenICam URL parsing, zipped/plain GenICam download -> arvzip.c / arv_gc_new) as it
 * talks to a camera on port 3956. The "camera" is a responder thread in this harness.
 *
 * Input format: a sequence of datagrams, each prefixed by a 2-byte big-endian length. The
 * responder answers each new GVCP command the client sends with the next datagram. Like a real
 * device, it echoes the command's 16-bit packet id into bytes 6-7 of its reply (the id is a
 * per-session counter the input cannot predict). Exceptions that keep each input's result a
 * function of the input alone, not of timing:
 *  - every reply is followed by a GVCP error ack (status ACCESS_DENIED) for the same command
 *    and packet id. If the reply was a valid ack the client has already returned and ignores
 *    the stale error ack (wrong packet id); otherwise the error ack ends the command at once,
 *    so the client never waits for its timeout. The build keeps upstream's 500 ms x 5 GVCP
 *    timeout, so a loaded host never makes the client give up on a reply that was sent;
 *  - a retransmission (same packet id and bytes as the last command the input answered) gets
 *    the last reply again, like a real device's ack cache, so it never consumes input;
 *  - the heartbeat's read of the CCP register (0x0a00), sent from a separate thread at its own
 *    pace, always gets a fixed "controlled" ack;
 *  - once the input is exhausted every command gets only the error ack.
 * Address: the camera and the client both use the loopback address private to this process
 * (mayhem/netshim.c: a random 127.x.y.z), bound WITHOUT SO_REUSEADDR, so fuzzer processes in
 * one network namespace never share a socket. Should the address still be taken by another
 * process, the harness picks a new random address and binds again; it never trades datagrams
 * with another process, and never ends the process over it.
 * Per input: a fresh server socket and responder thread (closed and joined at the end, so no
 * late command from one input can be answered with the next input's bytes),
 * arv_gv_device_new(addr, addr), register/memory reads and a few GenICam feature reads, then
 * unref (which joins the client's heartbeat thread). */
#include <arv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GVCP_PORT 3956

static GMutex lock;
static const uint8_t *cur_data = NULL;
static size_t cur_size = 0, cur_offset = 0;

typedef struct {
	int server_fd;
	int stop_fd;
} Responder;

static gpointer
responder (gpointer user_data)
{
	Responder *r = user_data;
	static unsigned char cmd[2048], reply[65536], last_cmd[2048];
	ssize_t last_cmd_len = -1;
	size_t last_len = 0;
	gboolean last_has_reply = FALSE;

	for (;;) {
		struct pollfd fds[2] = {{r->server_fd, POLLIN, 0}, {r->stop_fd, POLLIN, 0}};
		struct sockaddr_in from;
		socklen_t from_len = sizeof (from);
		unsigned char error_ack[8];
		guint16 ack_cmd;
		ssize_t n;

		if (poll (fds, 2, -1) < 0)
			continue;
		if (fds[1].revents != 0)
			break;
		n = recvfrom (r->server_fd, cmd, sizeof (cmd), MSG_DONTWAIT, (struct sockaddr *) &from, &from_len);
		if (n < 8 || cmd[0] != 0x42)
			continue;

		if (n >= 12 && cmd[2] == 0x00 && cmd[3] == 0x80 && cmd[4] == 0x00 && cmd[5] == 0x04 &&
		    cmd[8] == 0 && cmd[9] == 0 && cmd[10] == 0x0a && cmd[11] == 0x00) {
			/* READREG CCP (heartbeat): ack with value 2 (control access). */
			unsigned char ack[12] = {0x00, 0x00, 0x00, 0x81, 0x00, 0x04, cmd[6], cmd[7], 0, 0, 0, 2};
			(void) sendto (r->server_fd, ack, sizeof (ack), 0, (struct sockaddr *) &from, from_len);
			continue;
		}

		if (n != last_cmd_len || memcmp (cmd, last_cmd, n) != 0) {
			/* A new command: answer it with the input's next datagram, if any. A
			 * retransmission of the last command skips this and resends the same reply. */
			g_mutex_lock (&lock);
			last_has_reply = cur_data != NULL && cur_offset + 2 <= cur_size;
			last_len = 0;
			if (last_has_reply) {
				last_len = ((size_t) cur_data[cur_offset] << 8) | cur_data[cur_offset + 1];
				cur_offset += 2;
				if (last_len > cur_size - cur_offset)
					last_len = cur_size - cur_offset;
				memcpy (reply, cur_data + cur_offset, last_len);
				cur_offset += last_len;
				if (last_len >= 8) {
					reply[6] = cmd[6];
					reply[7] = cmd[7];
				}
			}
			g_mutex_unlock (&lock);
			memcpy (last_cmd, cmd, n);
			last_cmd_len = n;
		}

		if (last_has_reply)
			(void) sendto (r->server_fd, reply, last_len, 0, (struct sockaddr *) &from, from_len);

		/* Then a GVCP error ack (status 0x8006 ACCESS_DENIED) for this command and packet
		 * id: ignored if the reply above was accepted, otherwise it ends the command. */
		ack_cmd = (((guint16) cmd[2] << 8) | cmd[3]) + 1;
		error_ack[0] = 0x80;
		error_ack[1] = 0x06;
		error_ack[2] = ack_cmd >> 8;
		error_ack[3] = ack_cmd & 0xff;
		error_ack[4] = 0x00;
		error_ack[5] = 0x00;
		error_ack[6] = cmd[6];
		error_ack[7] = cmd[7];
		(void) sendto (r->server_fd, error_ack, sizeof (error_ack), 0, (struct sockaddr *) &from, from_len);
	}
	return NULL;
}

/* mayhem/netshim.c: this process's private loopback address. */
struct in_addr fuzz_loopback_address (void);
const char *fuzz_loopback_address_string (void);
void fuzz_loopback_repick (void);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	GInetAddress *lo;
	ArvDevice *device;
	GThread *thread;
	Responder r;
	struct sockaddr_in addr;
	const char *address;
	int stop[2];
	guint32 value;
	char memory[256];

	r.server_fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (r.server_fd < 0)
		return 0;
	for (;;) {
		memset (&addr, 0, sizeof (addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons (GVCP_PORT);
		addr.sin_addr = fuzz_loopback_address ();
		if (bind (r.server_fd, (struct sockaddr *) &addr, sizeof (addr)) == 0)
			break;
		if (errno != EADDRINUSE) {
			close (r.server_fd);
			return 0;
		}
		/* Another process holds this address's GVCP port: never share it (see the header). */
		fuzz_loopback_repick ();
	}
	address = fuzz_loopback_address_string ();
	if (pipe (stop) != 0) {
		close (r.server_fd);
		return 0;
	}
	r.stop_fd = stop[0];

	g_mutex_lock (&lock);
	cur_data = data;
	cur_size = size;
	cur_offset = 0;
	g_mutex_unlock (&lock);

	thread = g_thread_new ("gvcp-responder", responder, &r);

	lo = g_inet_address_new_from_string (address);
	device = arv_gv_device_new (lo, lo, NULL);
	g_object_unref (lo);

	if (device != NULL) {
		(void) arv_device_read_register (device, 0x0d04, &value, NULL);
		(void) arv_device_read_memory (device, 0x0048, sizeof (memory), memory, NULL);
		(void) arv_device_get_string_feature_value (device, "DeviceVendorName", NULL);
		(void) arv_device_get_integer_feature_value (device, "Width", NULL);
		(void) arv_device_get_integer_feature_value (device, "PayloadSize", NULL);
		g_object_unref (device);
	}

	(void) write (stop[1], "x", 1);
	g_thread_join (thread);
	close (stop[0]);
	close (stop[1]);
	close (r.server_fd);

	g_mutex_lock (&lock);
	cur_data = NULL;
	cur_size = cur_offset = 0;
	g_mutex_unlock (&lock);
	return 0;
}
