#include "main.h"

HMODULE		get_kernel32_base32(VOID)
{
	HMODULE			base_address;

	/*
	 xor ebx, ebx               // clear ebx
	 mov ebx, fs:[ 0x30 ]       // get a pointer to the PEB
	 mov ebx, [ ebx + 0x0C ]    // get PEB->Ldr
	 mov ebx, [ ebx + 0x14 ]    // get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	 mov ebx, [ ebx ]           // get the next entry (2nd entry)
	 mov ebx, [ ebx ]           // get the next entry (3rd entry)
	 mov ebx, [ ebx + 0x10 ]    // get the 3rd entries base address (kernel32.dll)
	*/
	__asm {
		xor		ebx, ebx
		mov		ebx, fs:[0x30]
		mov		ebx, [ebx + 0x0c]
		mov		ebx, [ebx + 0x14]
		mov		ebx, [ebx]
		mov		ebx, [ebx]
		mov		ebx, [ebx + 0x10]
		mov		base_address, ebx
	}

	return base_address;
}

HMODULE		get_local_dll_base(VOID)
{
	void		*base;

	__asm {
		nop
		call	delta
delta:
		pop		ebx
		and		ebx, 0ffff0000h
		xor		eax, eax

main_loop:
		mov		ax, [ebx]
		cmp		ax, 'ZM'
		je		exit_loop

		sub		ebx, 1000h
		jmp		main_loop

exit_loop:
		mov		base, ebx
	}

	return (HMODULE)base;
}
