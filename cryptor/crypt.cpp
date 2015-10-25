#pragma optimize("", off)

#include "crypt.h"
#include <stdint.h>

void crypt_chunk(uint8_t* chunk, int size, uint8_t mask)
{
	for (uint8_t* p = chunk; p < (chunk+size); p++)
		//*p = 0x42;
		*p ^= mask;
}
__declspec(naked) void __stdcall new_entry_point(void)
{
	__asm
	{
		push	0xFAFAFAFA
		push	0xFBFBFBFB
		push	0xFCFCFCFC
		call	crypt_chunk

		mov		eax, 0xFDFDFDFD
		jmp		eax
	}
}
__declspec(naked) int __stdcall end_point(void)
{
	__asm ret 1
}