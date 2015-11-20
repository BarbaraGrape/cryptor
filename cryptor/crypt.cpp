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
		if (!(rel->SizeOfBlock)) 
			break;
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
		call	get_eip
get_eip:
		pop		ecx // ecx is address of new_entry_point + 5

		sub		esp, 8
		mov		ebp, 0xFAFAFAFA // address of struct
		sub		ecx, [ebp]Some_data.nep_va // delta
		mov		[esp], ecx // delta
		mov		eax, [ebp]Some_data.cb_va
		lea		ebx, [ecx + eax]
		mov		[esp+4], ebx // base

		push	ebp // for save

		push	[ebp]Some_data.xor_mask
		push	[ebp]Some_data.code_vsize
		push	ebx
		call	crypt_chunk

		pop		ebp
		push	ebp

		//call rebasing
		mov		ecx, [esp+4]
		mov		ebx, [ebp]Some_data.br_va
		lea  	edx, [ecx + edx]
		push	[esp+8] // base
		push	[esp+8] // diff
		push	[ebp]Some_data.reloc_vsize // size of .reloc
		push	edx // point to .reloc
		call	rebase

		pop		ebp

		mov		eax, [ebp]Some_data.oep_va
		mov		ecx, [esp]
		lea		ebx, [ecx + eax]
		add		esp, 8
		jmp		ebx
	}
}
__declspec(naked) int __stdcall end_point(void)
{
	__asm ret 1
}