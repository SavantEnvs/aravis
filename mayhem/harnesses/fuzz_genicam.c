/* Fuzz the GenICam XML loader (arv_gc_new: libxml2 SAX -> ArvDom -> ArvGc node tree) and node
 * evaluation (feature values, integer/float bounds, enumerations, SwissKnife/Converter formulas,
 * register nodes). The XML is what a camera hands the host (GenICam URL / zip), so it is untrusted.
 * Register reads go to an in-process ArvFakeDevice created once; the harness only READS, so the
 * device state seen by every input is the same. */
#include <arv.h>
#include <stdint.h>

static ArvDevice *device = NULL;

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
	device = arv_fake_device_new ("FUZZ", NULL);
	return 0;
}

static void
walk (ArvDomNode *node, int depth)
{
	ArvDomNode *child;

	if (depth > 64)
		return;

	for (child = arv_dom_node_get_first_child (node); child != NULL;
	     child = arv_dom_node_get_next_sibling (child)) {
		GError *error = NULL;

		if (ARV_IS_GC_FEATURE_NODE (child)) {
			ArvGcFeatureNode *fn = ARV_GC_FEATURE_NODE (child);

			(void) arv_gc_feature_node_is_available (fn, &error);
			g_clear_error (&error);
			(void) arv_gc_feature_node_is_implemented (fn, &error);
			g_clear_error (&error);
			(void) arv_gc_feature_node_get_value_as_string (fn, &error);
			g_clear_error (&error);
		}
		if (ARV_IS_GC_INTEGER (child)) {
			ArvGcInteger *i = ARV_GC_INTEGER (child);

			(void) arv_gc_integer_get_value (i, &error);
			g_clear_error (&error);
			(void) arv_gc_integer_get_min (i, &error);
			g_clear_error (&error);
			(void) arv_gc_integer_get_max (i, &error);
			g_clear_error (&error);
			(void) arv_gc_integer_get_inc (i, &error);
			g_clear_error (&error);
		}
		if (ARV_IS_GC_FLOAT (child)) {
			ArvGcFloat *f = ARV_GC_FLOAT (child);

			(void) arv_gc_float_get_value (f, &error);
			g_clear_error (&error);
			(void) arv_gc_float_get_min (f, &error);
			g_clear_error (&error);
			(void) arv_gc_float_get_max (f, &error);
			g_clear_error (&error);
		}
		if (ARV_IS_GC_ENUMERATION (child)) {
			(void) arv_gc_enumeration_get_entries (ARV_GC_ENUMERATION (child));
		}

		walk (child, depth + 1);
	}
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	ArvGc *genicam;

	genicam = arv_gc_new (device, data, size);
	if (genicam == NULL)
		return 0;

	walk (ARV_DOM_NODE (genicam), 0);

	g_object_unref (genicam);
	return 0;
}
