/* Fuzz the zip reader (arvzip.c) used for zipped GenICam XML downloaded from devices:
 * central directory / local header parsing and inflate of every listed entry. */
#include <arv.h>
#include <stdint.h>

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	ArvZip *zip;
	const GSList *iter;

	zip = arv_zip_new (data, size);
	if (zip == NULL)
		return 0;

	for (iter = arv_zip_get_file_list (zip); iter != NULL; iter = iter->next) {
		const char *name = arv_zip_file_get_name (iter->data);
		size_t file_size = 0;
		void *content;

		if (name == NULL)
			continue;
		content = arv_zip_get_file (zip, name, &file_size);
		g_free (content);
	}

	arv_zip_free (zip);
	return 0;
}
