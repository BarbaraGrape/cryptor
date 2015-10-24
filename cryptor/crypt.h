#ifndef CRYPT_H
#define CRYPT_H

#include <stdint.h>

void crypt_chunk(uint8_t* chunk, int size, uint8_t mask);

#endif//CRYPT_H