BOOL		read_raw_into_buffer(	__in	LPCSTR	file_name,
									__out	PUINT	file_size,
									__out	LPVOID	*out_file);

BOOL		string_compare (		LPCSTR string1, 
									LPCSTR string2, 
									UINT max_length);

UINT		string_length(			LPCSTR input_string);

LPSTR		get_file_name_from_path(LPCSTR path);

PBYTE		generate_sha1(			PDWORD buffer,
									UINT buffer_size);

VOID		get_byte_hex(			__in	CHAR	b,
									__out	PCHAR	ch1,
									__out	PCHAR	ch2);

BOOL		create_registry_key(	HKEY	hive_key,
									LPCSTR	subkey,
									LPCSTR	key_name,
									DWORD	value);

LPSTR		unicode_to_ascii(		LPCWSTR string, 
									UINT	string_length);

UINT		get_unicode_string_length(LPCWSTR string);

VOID ascii_to_unicode(	__in		LPCSTR	ascii,
						__inout		LPWSTR	unicode);

BOOL		memory_compare(			PVOID	mem1,
									PVOID	mem2,
									UINT	count);

BYTE		generate_random_byte_range(UINT high);
DWORD generate_random_dword(VOID);

LPTHREAD_START_ROUTINE locate_dll_entry_point(		PDWORD							image,
													LPCSTR							export_name,
													PDWORD							remote_memory);

LPTHREAD_START_ROUTINE locate_dll_entry_point64(PDWORD image,
												LPCSTR export_name,
												PDWORD remote_memory);

BOOL write_raw_to_disk(	LPCSTR	file_name,
						PDWORD	buffer,
						UINT	size);

BOOL check_zeros(PBYTE buffer, UINT size);

BOOL get_shellcode_from_pe(	__in	PDWORD	buffer,
							__out	PDWORD	*shellcode,
							__out	PUINT	shellcode_size);

VOID				xVirtualFree(					DWORD32							base);
DWORD32	xVirtualAlloc(DWORD32 size);

DWORD read_registry_key(HKEY hive_key, LPCSTR subkey, LPCSTR key_name);
__declspec (dllexport) VOID set_memory(PBYTE i_memory, BYTE i_data, UINT i_length);
BSTR create_bstr(LPCWSTR resource_string);

VOID search_char(__inout LPSTR *ptr, __in CHAR character, BOOL direction);
VOID remove_filename_from_path(__in LPCSTR path);
BOOL compute_probability(UINT chance);

VOID xor32_data(DWORD key, PDWORD data, UINT size);