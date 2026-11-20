/* Fuzz arv_device_set_features_from_string (the feature-string tokenizer used by arv-tool,
 * the GStreamer plugin and applications), applied to an in-process ArvFakeDevice. The device
 * is created per input so writes by one input never leak into the next. */
#include <arv.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	ArvDevice *device;
	GError *error = NULL;
	char *string;

	device = arv_fake_device_new ("FUZZ", NULL);
	if (device == NULL)
		return 0;

	string = g_strndup ((const char *) data, size);
	(void) arv_device_set_features_from_string (device, string, &error);
	g_clear_error (&error);
	g_free (string);

	g_object_unref (device);
	return 0;
}
