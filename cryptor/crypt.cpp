#include "crypt.h"
#include <stdint.h>

void crypt_chunk(uint8_t* chunk, int size, uint8_t mask)
{
	for (uint8_t* p = chunk; p < (chunk+size); p++)
		*p = 0x42;
	//	*p ^= mask;
}