#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>
#include <Windows.h>

void __stdcall crypt_chunk(uint8_t* chunk, int size, uint8_t mask);
void __stdcall new_entry_point(void);
int __stdcall end_point();

struct Some_data
{
	DWORD nep_va;		// new entry point	
	DWORD cb_va;		// begin of code
	DWORD xor_mask;
	DWORD code_vsize;	// virtual size of code section
	DWORD oep_va;		// old entry point
	DWORD br_va;		// begin relocation
	DWORD reloc_vsize;
};

#endif//CRYPT_H