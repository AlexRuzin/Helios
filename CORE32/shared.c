#include "main.h"

BOOL read_raw_into_buffer(	__in	LPCSTR	file_name,
							__out	PUINT	file_size,
							__out	LPVOID	*out_file)
{
	ERROR_CODE			status;

	HANDLE				handle						= INVALID_HANDLE_VALUE;
	DWORD				size_high, size_low;
	PDWORD				buffer;
	DOUBLE				size;
	INT					junk;

	handle = CreateFileA(		file_name, 
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

BOOL string_compare (LPCSTR string1, LPCSTR string2, UINT max_length)
{
	INT			i;

	for (i = 0; i < max_length; i++) {
		if (string1[i] != string2[i]) {
			return 1;
		}
	}

	return 0;
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

VOID ascii_to_unicode(	__in		LPCSTR	ascii,
						__inout		LPWSTR	unicode)
{
	UINT		i;
	PWORD		ptr;

	ptr = (PWORD)unicode;
	for (i = 0; i < string_length(ascii); i++) {
		*(PBYTE)ptr = ascii[i];
		ptr++;
	}

	return;
}

LPSTR get_file_name_from_path(LPCSTR path)
{
	PBYTE	ptr;

	ptr = (PBYTE)path;

	while (*ptr != 0) {
		ptr++;
	}

	while (*ptr != '\\') {
		ptr--;
	}

	ptr++;

	return (LPSTR)ptr;
}

PBYTE generate_sha1(PDWORD buffer, UINT buffer_size)
{
	ERROR_CODE			status;

	HCRYPTPROV			crypto_provider;
	HCRYPTHASH			crypto_hash;

	DWORD				size;
	PBYTE				checksum;

	// Allocate memory for the checksum
	checksum = (PBYTE)HeapAlloc(GetProcessHeap(), 0, SIZEOF_SHA_SUM);
	ZeroMemory(checksum, SIZEOF_SHA_SUM);

	status = CryptAcquireContext(	&crypto_provider,
									NULL,
									NULL,
									PROV_RSA_FULL,
									CRYPT_VERIFYCONTEXT);
	if (!status) {
		return NULL;
	}


	status = CryptCreateHash(	crypto_provider,
								CALG_SHA,
								0,
								0,
								&crypto_hash);
	if (!status) {
		return NULL;
	}


	status = CryptHashData(		crypto_hash,
								(const PBYTE)buffer,
								(DWORD)buffer_size,
								0);
	if (!status) {
		return NULL;
	}

	status = CryptGetHashParam(	crypto_hash,
								HP_HASHVAL,
								checksum,
								&size,
								0);
	if (!status) {
		return NULL;
	}

	// Cleanup
	CryptDestroyHash(crypto_hash);
	CryptReleaseContext(crypto_provider, 0);

	return checksum;
}

VOID get_byte_hex(	__in	CHAR	b,
					__out	PCHAR	ch1,
					__out	PCHAR	ch2)
{
	CCHAR nybble_chars[] = "0123456789ABCDEF";

	*ch1 = nybble_chars[ ( b >> 4 ) & 0x0F ];
	*ch2 = nybble_chars[ b & 0x0F ];

	return;
}

BOOL create_registry_key(	HKEY	hive_key,
							LPCSTR	subkey,
							LPCSTR	key_name,
							DWORD	value)
{
	ERROR_CODE		status;
	HKEY			hive;
	HKEY			key;

	status = RegOpenKeyExA(	hive_key,
							NULL,
							0,
							KEY_WRITE,
							&hive);
	if (status != ERROR_SUCCESS) {
		return FALSE;
	}

	status = RegCreateKeyExA(	hive,
								subkey,
								0,
								NULL,
								0,
								KEY_WRITE,
								NULL,
								&key, 
								NULL);
	if (status != ERROR_SUCCESS) {
		RegCloseKey(hive);
		return FALSE;
	}

	RegSetValueExA(				key,
								key_name,
								0,
								REG_DWORD,
								(PBYTE)&value,
								sizeof(DWORD));

	// Cleanup
	RegCloseKey(key);
	RegCloseKey(hive);

	return TRUE;
}

LPSTR unicode_to_ascii(LPCWSTR string, UINT string_length)
{
	LPSTR			output_string,
					ptr_ascii;
	LPWSTR			ptr_unicode;
	UINT			i;

	output_string = (char *)HeapAlloc(GetProcessHeap(), 0, string_length / 2 + 1);
	ZeroMemory((void *)output_string, string_length / 2 + 1);

	ptr_ascii	= output_string;
	ptr_unicode	= (LPWSTR)string;
	for (i = 0; i < string_length; i += 2) {

		*ptr_ascii = *(char *)ptr_unicode;

		ptr_ascii++;
		ptr_unicode++;
	}
/*
	__asm {
				mov		esi, in_string
				mov		edi, output_string
				mov		ecx, in_string_length
				cld

unicode_to_ascii_loop:
				lodsb
				inc		esi
				stosb
				sub		ecx, 2
				cmp		ecx, 0
				jnle	unicode_to_ascii_loop
	}*/

	return	output_string;
}

UINT get_unicode_string_length(LPCWSTR string)
{
	UINT				length;
	PWORD				ptr;

	ptr	= (PWORD)string;

	length = 0;
	while (*ptr != 0) {
		ptr++;
		length +=2;
	}

	return length;
}

BOOL memory_compare(	PVOID	mem1,
						PVOID	mem2,
						UINT	count)
{
	UINT			i;

	for (i = 0; i < count; i++) {
		if (*(PBYTE)((SIZE_T)mem1 + i) != *(PBYTE)((SIZE_T)mem2 + i)) {
			return 1;
		}
	}

	return 0;
}

BYTE generate_random_byte_range(UINT high) 
{
	HCRYPTPROV				provider;
	BYTE					data[64]			= {0};
	UINT					i;

	if (high == 0) {
		return 0;
	}

	//Sleep(10);
	if (!CryptAcquireContextA(		&provider,
									NULL,
									NULL,
									PROV_RSA_FULL,
									CRYPT_VERIFYCONTEXT)) {
		return 0;
	}

	ZeroMemory(data, sizeof(data));
	data[0] = (BYTE)(high + 1);
	while (data[0] > high) {

		CryptGenRandom(provider, 32, data);

		for (i = 1; i < 64; i++) {

			data[0] ^= data[i];

			if (data[0] < high + 1) {
				return (BYTE)data[0];
			}
		}
	}

	CryptReleaseContext(provider, 0);

	return (BYTE)data[0];
}

DWORD generate_random_dword(VOID)
{
	HCRYPTPROV			provider			= 0;
	DWORD				key;

	CryptAcquireContext(	&provider,
							NULL,
							NULL,
							PROV_RSA_FULL,
							CRYPT_VERIFYCONTEXT);

	CryptGenRandom(provider, 4, (PBYTE)&key);

	CryptReleaseContext(provider, 0);

	return key;
}

LPTHREAD_START_ROUTINE locate_dll_entry_point(	PDWORD image,
												LPCSTR export_name,
												PDWORD remote_memory)
{
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;
	PIMAGE_EXPORT_DIRECTORY	eat;

	SYSTEM_INFO				system_info			= {0};

	DWORD					tmp;

	PDWORD					functions, names, function;
	PCHAR					name;

	GetNativeSystemInfo(&system_info);

#ifdef X86_OVERRIDE
	system_info.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif

	dos_header			= (PIMAGE_DOS_HEADER)image;
	nt_headers			= (PIMAGE_NT_HEADERS)((DWORD_PTR)image + dos_header->e_lfanew);
	//BREAK;
	if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		eat				= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	} else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		//BREAK;

#ifndef _WIN64
		eat				= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)image + nt_headers->OptionalHeader.DataDirectory[0x2].VirtualAddress);
#else
		eat				= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)image + nt_headers->OptionalHeader.DataDirectory[0x2].VirtualAddress);
#endif
	}

	functions			= (PDWORD)((DWORD_PTR)image + eat->AddressOfFunctions);
	names				= (PDWORD)((DWORD_PTR)image + eat->AddressOfNames);

	while (TRUE) {
		function		= (PDWORD)((DWORD_PTR)*functions);
		name			= (PCHAR)((DWORD_PTR)*names + (DWORD_PTR)image);

		if (!string_compare((LPCSTR)name, export_name, string_length(export_name))) {
			return (LPTHREAD_START_ROUTINE)((DWORD_PTR)function + (DWORD_PTR)remote_memory);
		}

		functions++;
		names++;
	}
}

LPTHREAD_START_ROUTINE locate_dll_entry_point64(	PDWORD image,
												LPCSTR export_name,
												PDWORD remote_memory)
{
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;
	PIMAGE_EXPORT_DIRECTORY	eat;

	SYSTEM_INFO				system_info			= {0};

	DWORD					tmp;

	PDWORD					functions, names, function;
	PCHAR					name;

	GetNativeSystemInfo(&system_info);

#ifdef X86_OVERRIDE
	system_info.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif

	dos_header			= (PIMAGE_DOS_HEADER)image;
	nt_headers			= (PIMAGE_NT_HEADERS)((DWORD_PTR)image + dos_header->e_lfanew);
	//BREAK;
	if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
		eat				= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)image + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	} else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
		//BREAK;

#ifndef _WIN64
		eat				= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)image + nt_headers->OptionalHeader.DataDirectory[0x2].VirtualAddress);
#else
		//BREAK;
		eat				= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)image + nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress);
#endif
	}

	//BREAK;
	functions			= (PDWORD)((DWORD_PTR)image + eat->AddressOfFunctions);
	names				= (PDWORD)((DWORD_PTR)image + eat->AddressOfNames);

	while (TRUE) 
	{
		//BREAK;
		function		= (PDWORD)((DWORD_PTR)*functions);
		name			= (PCHAR)((DWORD_PTR)*names + (DWORD_PTR)image);

		if (!string_compare((LPCSTR)name, export_name, string_length(export_name))) {
			return (LPTHREAD_START_ROUTINE)((DWORD_PTR)function + (DWORD_PTR)remote_memory);
		}

		functions++;
		names++;
	}
}

BOOL check_zeros(PBYTE buffer, UINT size) 
{
	BYTE			*ptr;
	UINT			i;

	for (i = 0, ptr = buffer; i < size; i++, ptr++) {
		if (*ptr != 0) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL get_shellcode_from_pe(	__in	PDWORD	buffer,
							__out	PDWORD	*shellcode,
							__out	PUINT	shellcode_size)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header;

	PBYTE						ptr;
	UINT						i;

	// Get headers
	dos_header			= (PIMAGE_DOS_HEADER)((SIZE_T)buffer);
	nt_headers			= (PIMAGE_NT_HEADERS)((SIZE_T)buffer + (DWORD)dos_header->e_lfanew);
	section_header		= (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers);

	// Return start of shellcode & adjust
	*shellcode			= (PDWORD)((SIZE_T)buffer + (DWORD)section_header->PointerToRawData);
	*shellcode			= (PDWORD)((DWORD_PTR)*shellcode + (UINT)(nt_headers->OptionalHeader.AddressOfEntryPoint - section_header->VirtualAddress));
	
	i = 0;
	ptr = (PBYTE)*shellcode;
	while (TRUE) {

		if ((*(PDWORD)ptr == 0) && (*(PDWORD)((DWORD_PTR)ptr + 4) == 0)) {
			break;
		}

		ptr++;
		i++;
	}

	*shellcode_size = i;

	return TRUE;
}


DWORD32	xVirtualAlloc(DWORD32 size)
{
	DWORD32		return_base;

	return_base = (DWORD32)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	return return_base;
}

VOID xVirtualFree(DWORD32 base)
{
	MEMORY_BASIC_INFORMATION mem_info = {0};

	VirtualQuery(base, &mem_info, sizeof(MEMORY_BASIC_INFORMATION));

	VirtualFree(base, mem_info.RegionSize, MEM_DECOMMIT);

	return;
}

DWORD read_registry_key(HKEY hive_key, LPCSTR subkey, LPCSTR key_name)
{
	DWORD		return_value = -1;
	DWORD		size_of_value = sizeof(DWORD);
	HKEY		key;

	RegOpenKeyExA(	hive_key,
					subkey,
					NULL,
					KEY_READ,
					&key);

	RegQueryValueExA(	key,
						key_name,
						NULL,
						NULL,
						(LPBYTE)&return_value,
						&size_of_value);


/*
unsigned long type=REG_SZ, size=1024;
 char res[1024]="";
 HKEY key;


 if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\YOUR KEY",
 NULL, KEY_READ, &key)==ERROR_SUCCESS){

 RegQueryValueEx(key,
 "Path",// YOUR value
 NULL,
 &type,
 (LPBYTE)&res[0],
 &size);
 RegCloseKey(key);
 }*/

	return return_value;
}


__declspec (dllexport) VOID set_memory(PBYTE i_memory, BYTE i_data, UINT i_length)
{
	BYTE			*ptr;
	unsigned int	i;

	ptr = (PBYTE)i_memory;
	for (i = 0; i < i_length; i++) {
		*(PBYTE)((DWORD)ptr + i) = 0;
	}


	/*
	__asm {
				mov		edi, i_memory
				mov		ecx, i_length
				mov		al, i_data
				cld
				rep		stosb
	}*/
}

BSTR create_bstr(LPCWSTR resource_string)
{
	unsigned int		resource_string_length;
	BSTR				resource;

	resource_string_length = get_unicode_string_length(resource_string);
	resource = (BSTR)HeapAlloc(GetProcessHeap(), 0, 4 + resource_string_length + 6);
	ZeroMemory(resource, 4 + resource_string_length + 6);
	*resource = (DWORD)resource_string_length;
	resource = (BSTR)((char *)resource + 4);
	CopyMemory(resource, resource_string, resource_string_length);

	return resource;
}

VOID search_char(__inout LPSTR *ptr, __in CHAR character, BOOL direction)
{
	PCHAR		pointer = *ptr;

	if (direction == SEARCH_CHAR_BACKWARD) {
		while (*pointer != character) {
			pointer--;
		}
	} else if (direction == SEARCH_CHAR_FORWARD) {
		while (*pointer != character) {
			pointer++;
		}
	}

	*ptr = pointer;

	return;
}

VOID remove_filename_from_path(__in LPCSTR path)
{
	PCHAR		pointer;

	pointer = (PCHAR)((DWORD_PTR)path + string_length(path));

	search_char(&pointer, '\\', SEARCH_CHAR_BACKWARD);
	ZeroMemory(pointer, string_length(pointer));

	return;
}

BOOL compute_probability(UINT chance)
{

	if (chance == 0) {
		return FALSE;
	} else if (chance == 100) {
		return TRUE;
	} else if (chance > 100) {
		return FALSE;
	}

	// Input should be 1-100 (% chance)
	if (generate_random_byte_range(100) < chance) {
		return TRUE;
	} else {
		return FALSE;
	}

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

