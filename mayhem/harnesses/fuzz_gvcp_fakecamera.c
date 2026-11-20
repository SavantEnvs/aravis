/* Fuzz the GigE Vision control protocol (GVCP) server side: ArvGvFakeCamera's control packet
 * handler (arvgvfakecamera.c _handle_control_packet, arvgvcp.c, arvfakecamera.c register and
 * memory access), reached the way a remote host reaches it: UDP datagrams to port 3956.
 *
 * Input format: a sequence of datagrams, each prefixed by a 2-byte big-endian length.
 * A fresh fake camera is started per input, so register writes never leak between inputs; its
 * thread is joined by g_object_unref (arv_gv_fake_camera_stop) before the next input starts.
 * The datagrams are delivered in lockstep: after each one the harness sends a READREG command
 * with a sentinel packet id and waits for its acknowledge. The camera handles packets in order
 * on one socket, so that ack means the fuzz datagram has been processed, and at most two
 * datagrams are ever queued, so loopback UDP never drops one for a full socket buffer. Should
 * the sentinel or its ack still be lost, the receive times out after 200 ms and the sentinel is
 * sent again, at most SENTINEL_TRIES times in all (the retry policy of aravis's own GVCP client,
 * arvgvdevice.c: 5 tries); after that the input ends normally, so a slow camera never turns into
 * a per-exec timeout.
 *
 * Streaming is kept off: once each datagram is acknowledged, the harness writes 0 to the fake
 * camera's AcquisitionStart register (ARV_FAKE_CAMERA_REGISTER_ACQUISITION) through its public
 * API. The fuzzed surface is the control-packet handler; the camera's frame sender is test-device
 * code that runs on its own 100 ms clock, and the image size and packet size it uses come from
 * fuzzed registers (a 4 GB frame, or a packet size equal to the GVSP overhead, which makes its
 * send loop spin forever), so whether an input reached it depended on timing, not on the input.
 * Register writes themselves (width, height, packet size, stream address, ...) still go through
 * the handler and are read back by later datagrams.
 *
 * Address: the camera listens on, and the harness sends to, this process's private loopback
 * address (mayhem/netshim.c: a random 127.x.y.z, which the fake camera sees as "lo"'s address),
 * so fuzzer processes sharing a network namespace never send to each other's camera. The fake
 * camera reports itself running even when its GVCP bind fails, so before starting it the harness
 * checks that address:3956 is free, and after starting it that the port is now held. If either
 * check fails (another process holds it) the harness picks a new random address and starts the
 * camera again; it never trades datagrams with another process, and never ends the process over it.
 */
#include <arv.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define GVCP_PORT 3956
#define SENTINEL_ID 0xfeed
#define SENTINEL_TRIES 5
/* mayhem/netshim.c: this process's private loopback address. */
struct in_addr fuzz_loopback_address (void);
const char *fuzz_loopback_address_string (void);
void fuzz_loopback_repick (void);
int fuzz_loopback_port_free (unsigned short port);

/* Send the sentinel READREG and wait for its ack, resending it if nothing arrives within 200 ms,
 * SENTINEL_TRIES sends in all. Returns 1 once acknowledged, 0 if the camera never answered. */
static int
sync_with_camera (int fd)
{
	static const unsigned char sentinel[12] = {0x42, 0x01, 0x00, 0x80, 0x00, 0x04,
						   SENTINEL_ID >> 8, SENTINEL_ID & 0xff, 0x00, 0x00, 0x00, 0x00};
	unsigned char reply[2048];
	int tries = 1;

	(void) send (fd, sentinel, sizeof (sentinel), 0);
	for (;;) {
		ssize_t n = recv (fd, reply, sizeof (reply), 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if ((errno == EAGAIN || errno == EWOULDBLOCK) && tries < SENTINEL_TRIES) {
				tries++;
				(void) send (fd, sentinel, sizeof (sentinel), 0);
				continue;
			}
			return 0;
		}
		if (n >= 8 && reply[0] == 0x00 && reply[2] == 0x00 && reply[3] == 0x81 &&
		    reply[6] == (SENTINEL_ID >> 8) && reply[7] == (SENTINEL_ID & 0xff))
			return 1;
	}
}

/* Keep the fake camera's frame sender off (see the header comment). */
static void
stop_acquisition (ArvGvFakeCamera *camera)
{
	arv_fake_camera_write_register (arv_gv_fake_camera_get_fake_camera (camera),
					ARV_FAKE_CAMERA_REGISTER_ACQUISITION, 0);
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	ArvGvFakeCamera *camera;
	struct sockaddr_in addr;
	struct timeval rcv_timeout = {0, 200000};
	size_t offset = 0;
	int fd;

	for (;;) {
		if (!fuzz_loopback_port_free (GVCP_PORT)) {
			fuzz_loopback_repick ();
			continue;
		}
		camera = arv_gv_fake_camera_new (fuzz_loopback_address_string (), "FUZZ");
		if (camera == NULL || !arv_gv_fake_camera_is_running (camera)) {
			g_clear_object (&camera);
			return 0;
		}
		if (!fuzz_loopback_port_free (GVCP_PORT))
			break;	/* held, by this camera */
		/* The camera's GVCP bind failed: another process took the port in between. */
		g_object_unref (camera);
		fuzz_loopback_repick ();
	}

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	memset (&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons (GVCP_PORT);
	addr.sin_addr = fuzz_loopback_address ();
	if (fd < 0 || setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeout, sizeof (rcv_timeout)) != 0 ||
	    connect (fd, (struct sockaddr *) &addr, sizeof (addr)) != 0) {
		if (fd >= 0)
			close (fd);
		g_object_unref (camera);
		return 0;
	}

	while (offset + 2 <= size) {
		size_t len = ((size_t) data[offset] << 8) | data[offset + 1];

		offset += 2;
		if (len > size - offset)
			len = size - offset;
		(void) send (fd, data + offset, len, 0);
		offset += len;
		if (!sync_with_camera (fd))
			break;
		stop_acquisition (camera);
	}
	stop_acquisition (camera);
	(void) sync_with_camera (fd);

	close (fd);
	g_object_unref (camera);
	return 0;
}
