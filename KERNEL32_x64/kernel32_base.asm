section .text
	global _start

_start:
use64
	nop

	xor rdx, rdx
	mov rdx, [fs:rdx+0x60]  ; rdx = address of PEB
	mov rdx, [rdx+0x18]     ; rdx = address of Ldr
	mov rdx, [rdx+0x20]     ; rdx = first module entry address
	mov rdx, [rdx]          ; rdx = second module entry address
	mov rdx, [rdx]          ; rdx = third module entry address
	mov rdx, [rdx+0x20]     ; rdx = DllBase of kernel32.dll

	ret
