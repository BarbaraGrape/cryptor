#pragma optimize("", off)

#include "crypt.h"
#include <stdint.h>

void __stdcall crypt_chunk(uint8_t* chunk, int size, uint8_t mask)
{
	for (uint8_t* p = chunk; p < (chunk+size); p++)
		//*p = 0x42;
		*p ^= mask;
}
__declspec(naked) void __stdcall new_entry_point(void)
{
	__asm
	{
		call	get_eip
get_eip:
		pop		ecx
		sub		ecx, 0xFDFDFDFD // delta
		lea		ebx, [ecx + 0xFAFAFAFA]
		push	ecx
		push	0xFBFBFBFB
		push	0xFCFCFCFC
		push	ebx
		call	crypt_chunk

		pop		ecx
		lea		ebx, [ecx + 0xFDFDFDFD]
		jmp		ebx
	}
}
__declspec(naked) int __stdcall end_point(void)
{
	__asm ret 1
}