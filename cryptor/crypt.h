#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>


const int MASK_OFFSET		= 1;
const int SIZE_OFFSET		= MASK_OFFSET + 5;
const int CHUNK_OFFSET		= SIZE_OFFSET + 5;
const int OLD_ENTRY_OFFSET	= CHUNK_OFFSET + 10;

void crypt_chunk(uint8_t* chunk, int size, uint8_t mask);
void __stdcall new_entry_point(void);
int __stdcall end_point();

#endif//CRYPT_H