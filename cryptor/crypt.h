#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>

void crypt_chunk(uint8_t* chunk, int size, uint8_t mask);
void __stdcall new_entry_point(void);
int __stdcall end_point();

#endif//CRYPT_H