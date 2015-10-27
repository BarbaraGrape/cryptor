#pragma optimize("", off)

#include "crypt.h"
#include <stdint.h>
#include <Windows.h>

void __stdcall crypt_chunk(uint8_t* chunk, int size, uint8_t mask)
{
	for (uint8_t* p = chunk; p < (chunk+size); p++)
		//*p = 0x42;
		*p ^= mask;
}
void __stdcall rebase(BYTE* ptable, uint32_t size, int diff, int base)
{
	BYTE *pend = ptable + size;
	while ( ptable < pend )
	{
		IMAGE_BASE_RELOCATION* rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ptable);
		for (WORD* p = reinterpret_cast<WORD*>(ptable + sizeof(IMAGE_BASE_RELOCATION)); p <  reinterpret_cast<WORD*>(ptable + rel->SizeOfBlock); p++)
		{
			int type = (*p & 0xf000) >> 12;
			int location = (*p & 0x0fff) + rel->VirtualAddress - 0x1000; //todo 
			switch(type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				{
					DWORD b = *reinterpret_cast<DWORD*>(base+location) + diff;
					*reinterpret_cast<DWORD*>(base+location) = b;
					break;
				}
			default:
				break;
			}
		}
		ptable += rel->SizeOfBlock;
	}
}
__declspec(naked) void __stdcall new_entry_point(void)
{
	__asm
	{
		sub		esp, 8
		call	get_eip
get_eip:
		pop		ecx
		sub		ecx, 0xFDFDFDFD // delta
		mov		[esp], ecx // delta
		lea		ebx, [ecx + 0xFAFAFAFA]
		mov		[esp+4], ebx // base
		push	0xFBFBFBFB
		push	0xFCFCFCFC
		push	ebx
		call	crypt_chunk

		//call rebasing
		mov		ecx, [esp]
		lea  	edx, [ecx + 0xF1F1F1F1]
		push	[esp+4] // base
		push	[esp+4] // diff
		push	0xF2F2F2F2 // size of .reloc
		push	edx // point to .reloc
		call	rebase

		mov		ecx, [esp]
		lea		ebx, [ecx + 0xFDFDFDFD]
		add		esp, 8
		jmp		ebx
	}
}
__declspec(naked) int __stdcall end_point(void)
{
	__asm ret 1
}