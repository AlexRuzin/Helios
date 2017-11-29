#include "main.h"

VOID fix_image_base_relocs(	PBYTE	image_base,
							PDWORD	remote_image,
							PBYTE	remote_image_base)
{
	PIMAGE_DOS_HEADER		dos_header;
	PIMAGE_NT_HEADERS		nt_headers;
	PIMAGE_BASE_RELOCATION	base_reloc;

	ULONG					base_delta;
	UINT					reloc_entries,
							i;
	PUCHAR					destination;
	PUSHORT					reloc_info;

	dos_header	= (PIMAGE_DOS_HEADER)image_base;
	nt_headers	= (PIMAGE_NT_HEADERS)((SIZE_T)image_base + dos_header->e_lfanew);
	base_reloc	= (PIMAGE_BASE_RELOCATION)	(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress +
											(SIZE_T)image_base);

	// Do we need to relocate?
	if ((DWORD)remote_image_base == (DWORD)nt_headers->OptionalHeader.ImageBase) {
		return;
	}

	base_delta = (ULONG)((DWORD)remote_image_base - (DWORD)nt_headers->OptionalHeader.ImageBase);

	while (TRUE) {
		reloc_entries = (base_reloc->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2;
		destination = (PUCHAR)CALCULATE_ADDRESS((DWORD)image_base, (DWORD)base_reloc->VirtualAddress);
        reloc_info = (PUSHORT)((SIZE_T)base_reloc + IMAGE_SIZEOF_BASE_RELOCATION);

		for (i = 0; i < reloc_entries; i++) {
			if (((*reloc_info >> 12) & IMAGE_REL_BASED_HIGHLOW)) {
				__nop;

				/*
				__asm {
						mov		ebx, reloc_info
						mov		ebx, [ebx]
						and		
				}*/


				*MakePtr(unsigned long *, destination, (*reloc_info & 0x0fff)) += base_delta;
				/*
				__asm {
					mov		eax, [reloc_info]
					movzx	ecx, [eax]
					and		ecx, 0fffh
					mov		edx, [destination]
					mov		eax, [edx + ecx]
					add		eax, [base_delta]
					mov		ecx, [reloc_info]
					movzx	edx, [ecx]
					and		edx, 0fffh
					mov		ecx, [destination]
					mov		[ecx + edx], eax
					nop
				}
				*/
				__nop;
			}

			reloc_info = (PUSHORT)((SIZE_T)reloc_info + (IMAGE_SIZEOF_BASE_RELOCATION / 4));
		}

		base_reloc = (PIMAGE_BASE_RELOCATION)((SIZE_T)base_reloc + base_reloc->SizeOfBlock);

	}

	return;
}