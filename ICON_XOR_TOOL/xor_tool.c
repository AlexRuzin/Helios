#include <Windows.h>
#include "..\CORE32\config.h"
#include "..\CORE32\shared.h"

INT main(VOID) 
{
	PDWORD			buffer;
	UINT			size;

	read_raw_into_buffer("J:\\annas_worm\\_icons\\docx-icon.ico", &size, &buffer);

	xor32_data(ICON_DATA_XOR_KEY, buffer, size);

	write_raw_to_disk("J:\\annas_worm\\_icons\\resources\\docx-icon.bin", buffer, size);

	return 0;
}