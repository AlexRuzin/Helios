#include "../CORE32/main.h"
//#include "resource.h"

HANDLE	(__stdcall *f_loadlibrarya)(LPCSTR lpFileName);
QWORD	(__stdcall *f_getprocaddressa)(HANDLE hModule, LPCSTR lpProcName);
BOOL	(__stdcall *f_isbadreadptr)(const VOID *lp, UINT_PTR usb);

VOID resolve_local_api64(VOID)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		section_header;
	PIMAGE_IMPORT_DESCRIPTOR	import_descriptor;
	PIMAGE_IMPORT_BY_NAME		import_by_name;
	PIMAGE_THUNK_DATA64			thunk_data;

	QWORD						ordinal_function, name_function;
	PDWORD						kernel32;
	PDWORD						module;
	HMODULE						ntdll;

	DWORD						import_by_ordinal, file_offset;
	PDWORD						image_base;

	PCHAR						module_name;
	ULONG						orginal_value;
	UINT						i						= 0;

	// Resolve kernel32 functions - FIXME proper return checking
	kernel32			= (PDWORD)get_kernel32_base64();
	f_getprocaddressa	= (QWORD (__stdcall *)(HANDLE, LPCSTR))resolve_export64(kernel32, "GetProcAddress");
	f_loadlibrarya		= (HANDLE(__stdcall *)(LPCSTR))resolve_export64(kernel32, "LoadLibraryA");
	f_isbadreadptr		= (BOOL (__stdcall *)(const VOID *, UINT_PTR))resolve_export64(kernel32, "IsBadReadPtr");

	// Get local base
	image_base			= (PDWORD)get_local_dll_base64();
	
	// Setup headers
	dos_header = (PIMAGE_DOS_HEADER)image_base;
	nt_headers = (PIMAGE_NT_HEADERS)((SIZE_T)image_base + dos_header->e_lfanew);
	section_header = IMAGE_FIRST_SECTION(nt_headers);

	file_offset = (DWORD)((nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - section_header->VirtualAddress) + section_header->Misc.PhysicalAddress);
	import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((SIZE_T)image_base + (DWORD)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (TRUE) {
		module_name = (PCHAR)((DWORD)import_descriptor->Name + (SIZE_T)image_base);
		module		= (PDWORD)f_loadlibrarya(module_name);

		if (module == NULL) {
			//DbgPrint("Import Error in library %s", module_name);

			import_descriptor++;
			if (import_descriptor->OriginalFirstThunk == 0) break;

			continue;
		}

		thunk_data = (PIMAGE_THUNK_DATA64)((SIZE_T)image_base + import_descriptor->FirstThunk);

		// ORDINAL
		if (thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
			while (TRUE) {
imports_ordinal:

				if (thunk_data->u1.AddressOfData == 0) break;

				if (!(thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
					goto imports_name;
				}

				//import_by_ordinal = (PIMAGE_IMPORT_BY_NAME)(thunk_data->u1.AddressOfData + (SIZE_T)image_base);
				//import_by_ordinal = MAKELONG(import_by_ordinal,0);
				ordinal_function = (QWORD)f_getprocaddressa(module, (LPCSTR)(thunk_data->u1.AddressOfData & 0x00000000ffffffff));
				if (ordinal_function == NULL) {
					goto imports_name;
				}

				if ((QWORD)ordinal_function == thunk_data->u1.Function) {
					thunk_data++;
					continue;
				} else {
					//test = (DWORD)thunk_data->u1.Function + (DWORD)image_base;
					thunk_data->u1.Function = (QWORD)ordinal_function;
				}
				thunk_data++;
			}
		// RVA (name)
		} else {
			while (TRUE) {
imports_name:
				if (thunk_data->u1.AddressOfData == 0) break;

				if (thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					goto imports_ordinal;
				}

				import_by_name = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)thunk_data->u1.AddressOfData + (SIZE_T)image_base);
				if (f_isbadreadptr(import_by_name->Name, 4)) {
					thunk_data++;
					continue;
				}
				
				// FIXME
				if (!string_compare((LPCSTR)import_by_name->Name, "memset", (UINT)string_length("memset"))) {
					thunk_data++;
					continue;
				}

				name_function = (QWORD)f_getprocaddressa(module, (char *)import_by_name->Name);

				if (name_function == NULL) {
					thunk_data++;
					continue;
				}

				if (name_function == thunk_data->u1.Function) {
					thunk_data++;
					continue;
				} else {
					//test = (DWORD)thunk_data->u1.Function + (DWORD)image_base;
					thunk_data->u1.Function = name_function;
				}
				thunk_data++;
			}
		}
		import_descriptor++;
		if (import_descriptor->OriginalFirstThunk == 0) break;
	}

	// CRT functions
	ntdll		= GetModuleHandleA("ntdll.dll");
	f_itoa		= (char (*)(int, char *, int))GetProcAddress(ntdll, "_itoa");
	f_snprintf	= (int (*)(char *, SIZE_T, const char *, ...))GetProcAddress(ntdll, "_snprintf");
	//f_system	= (int (*)(const char *))GetProcAddress(ntdll, "system");
	f_atoi		= (int (*)(const char *))GetProcAddress(ntdll, "atoi");
	f_strncmp	= (int (*)(const char *, const char *, SIZE_T))GetProcAddress(ntdll, "strncmp");
	f_memcpy	= (void (*)(void *, const void *, SIZE_T))GetProcAddress(ntdll, "memcpy");


	return;
}

LPVOID resolve_export64(PDWORD module, LPCSTR function)
{
	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_EXPORT_DIRECTORY		eat;

	PDWORD						name_ptr, addr_ptr;
	PWORD						ordinal_ptr;
	LPVOID						return_function;
	PCHAR						name_string;
	UINT						i, ordinal;

	dos_header	= (PIMAGE_DOS_HEADER)module;
	nt_headers	= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	eat			= (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)dos_header + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	name_ptr	= (PDWORD)	((DWORD_PTR)dos_header + eat->AddressOfNames);
	ordinal_ptr	= (PWORD)	((DWORD_PTR)dos_header + eat->AddressOfNameOrdinals);

	ordinal = -1;
	for (i = 0; i < eat->NumberOfNames; i++) {

		name_string = (PCHAR)((DWORD_PTR)dos_header + name_ptr[i]);

		if (string_compare(name_string, function, string_length(function)) == 0) {
			ordinal = (UINT)ordinal_ptr[i];
			break;
		}

	}

	if (ordinal != -1) {
		addr_ptr		= (PDWORD)((DWORD_PTR)dos_header + eat->AddressOfFunctions);
		return_function	= (LPVOID)((DWORD_PTR)dos_header + addr_ptr[ordinal]);
	}

	return return_function;

}

QWORD	get_kernel32_base64(VOID)
{
	PCHAR		shellcode_runtime;
	QWORD		(*shellcode_ptr)(VOID);
	QWORD		kernel32_base;

	shellcode_ptr = (QWORD (*)(VOID))get_kernel32_64;

	kernel32_base = shellcode_ptr();

	return kernel32_base;
}

