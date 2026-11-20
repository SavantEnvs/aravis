/* Fuzz the GigE Vision streaming protocol (GVSP) receiver: ArvGvStream's packet processing
 * (arvgvstream.c _process_packet / frame reassembly / resend logic, arvgvspprivate.h accessors,
 * arvgvsp.c) and the ArvBuffer getters applications call on the frames it completes (image,
 * multipart, chunk and GenDC data). Packets reach it the way a camera sends them: UDP
 * datagrams to the stream port.
 *
 * Setup (once): an in-process ArvGvFakeCamera and an ArvGvDevice connected to it, both on this
 * process's private loopback address (mayhem/netshim.c: a random 127.x.y.z; the harness picks
 * another until the camera holds the GVCP port of its own), so no other fuzzer process's GVCP
 * traffic reaches this camera and this device never talks to theirs. The camera never starts acquisition, so the only GVSP traffic is the fuzz input.
 * The stream uses a plain UDP socket (ARV_GV_STREAM_OPTION_PACKET_SOCKET_DISABLED): the PF_PACKET
 * path depends on CAP_NET_RAW, which would make Mayhem and local runs take different code paths.
 * Per input: a fresh stream (so no frame state carries over) with 4 buffers; the input is a
 * sequence of at most MAX_DATAGRAMS datagrams, each prefixed by a 2-byte big-endian length. The
 * harness waits until the stream thread has counted every datagram (n_received_packets), or until
 * WAIT_DEADLINE_US passes (a datagram the kernel dropped would otherwise stall the input; the
 * deadline only ends the wait), then pops and inspects whatever buffers it completed. */
#include <arv.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* mayhem/netshim.c: this process's private loopback address. */
struct in_addr fuzz_loopback_address (void);
const char *fuzz_loopback_address_string (void);
void fuzz_loopback_repick (void);
int fuzz_loopback_port_free (unsigned short port);

#define MAX_TOTAL_BYTES 65536	/* payload cap */
#define MAX_DATAGRAMS 256	/* datagram cap: each costs a full skb against the receive buffer */
#define WAIT_DEADLINE_US (2 * G_USEC_PER_SEC)
#define N_BUFFERS 4

static ArvGvFakeCamera *camera = NULL;
static ArvDevice *device = NULL;
static gint64 payload = 0;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
	GInetAddress *lo;

	for (;;) {
		if (!fuzz_loopback_port_free (3956)) {
			fuzz_loopback_repick ();
			continue;
		}
		camera = arv_gv_fake_camera_new (fuzz_loopback_address_string (), "FUZZ");
		if (camera == NULL || !arv_gv_fake_camera_is_running (camera) || !fuzz_loopback_port_free (3956))
			break;	/* the camera holds its GVCP port (or could not start at all) */
		/* The camera's GVCP bind failed: another process took the port in between. */
		g_object_unref (camera);
		fuzz_loopback_repick ();
	}
	lo = g_inet_address_new_from_string (fuzz_loopback_address_string ());
	device = arv_gv_device_new (lo, lo, NULL);
	g_object_unref (lo);
	if (device != NULL)
		arv_gv_device_set_stream_options (ARV_GV_DEVICE (device),
						  ARV_GV_STREAM_OPTION_PACKET_SOCKET_DISABLED);
	if (device != NULL)
		payload = arv_device_get_integer_feature_value (device, "PayloadSize", NULL);
	if (payload <= 0 || payload > (64 << 20))
		payload = 512 * 512;
	return 0;
}

static void
inspect (ArvBuffer *buffer)
{
	size_t size;
	guint i, n_parts;
	gint x, y, w, h;

	(void) arv_buffer_get_status (buffer);
	(void) arv_buffer_get_frame_id (buffer);
	(void) arv_buffer_get_timestamp (buffer);
	(void) arv_buffer_get_data (buffer, &size);
	if (arv_buffer_get_status (buffer) != ARV_BUFFER_STATUS_SUCCESS)
		return;
	switch (arv_buffer_get_payload_type (buffer)) {
		case ARV_BUFFER_PAYLOAD_TYPE_IMAGE:
		case ARV_BUFFER_PAYLOAD_TYPE_EXTENDED_CHUNK_DATA:
			(void) arv_buffer_get_image_data (buffer, &size);
			arv_buffer_get_image_region (buffer, &x, &y, &w, &h);
			(void) arv_buffer_get_image_pixel_format (buffer);
			break;
		default:
			break;
	}
	n_parts = arv_buffer_get_n_parts (buffer);
	for (i = 0; i < n_parts && i < 16; i++) {
		(void) arv_buffer_get_part_data (buffer, i, &size);
		(void) arv_buffer_get_part_pixel_format (buffer, i);
		arv_buffer_get_part_region (buffer, i, &x, &y, &w, &h);
	}
	if (arv_buffer_has_chunks (buffer)) {
		(void) arv_buffer_get_chunk_data (buffer, 0x1, &size);
		(void) arv_buffer_get_chunk_data (buffer, 0xffffffff, &size);
	}
	if (arv_buffer_has_gendc (buffer)) {
		(void) arv_buffer_get_gendc_descriptor (buffer, &size);
		(void) arv_buffer_get_gendc_data (buffer, &size);
	}
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	ArvStream *stream;
	ArvBuffer *buffer;
	struct sockaddr_in addr;
	size_t offset = 0, total = 0;
	guint64 n_sent = 0;
	int fd, i;

	if (device == NULL)
		return 0;

	stream = arv_device_create_stream (device, NULL, NULL, NULL, NULL);
	if (stream == NULL)
		return 0;
	for (i = 0; i < N_BUFFERS; i++)
		arv_stream_push_buffer (stream, arv_buffer_new_allocate (payload));
	if (!arv_stream_start_acquisition (stream, NULL)) {
		g_object_unref (stream);
		return 0;
	}

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	memset (&addr, 0, sizeof (addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons (arv_gv_stream_get_port (ARV_GV_STREAM (stream)));
	addr.sin_addr = fuzz_loopback_address ();

	if (fd >= 0 && connect (fd, (struct sockaddr *) &addr, sizeof (addr)) == 0) {
		gint64 deadline;

		while (offset + 2 <= size && total < MAX_TOTAL_BYTES && n_sent < MAX_DATAGRAMS) {
			size_t len = ((size_t) data[offset] << 8) | data[offset + 1];

			offset += 2;
			if (len > size - offset)
				len = size - offset;
			if (send (fd, data + offset, len, 0) == (ssize_t) len)
				n_sent++;
			offset += len;
			total += len + 2;
		}
		/* Wait until the stream thread saw every datagram; the deadline only ends the wait (in
		 * case the kernel dropped one), it does not fail the input. */
		deadline = g_get_monotonic_time () + WAIT_DEADLINE_US;
		while (arv_stream_get_info_uint64_by_name (stream, "n_received_packets") < n_sent &&
		       g_get_monotonic_time () < deadline)
			g_usleep (50);
	}
	if (fd >= 0)
		close (fd);

	arv_stream_stop_acquisition (stream, NULL);
	while ((buffer = arv_stream_try_pop_buffer (stream)) != NULL) {
		inspect (buffer);
		g_object_unref (buffer);
	}

	g_object_unref (stream);
	return 0;
}
