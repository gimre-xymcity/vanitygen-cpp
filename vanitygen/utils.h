#pragma once

#include "pcg/pcg_basic.h"
#include <stdint.h>

void randombytes(unsigned char* _data, size_t dataSize);
void fill(pcg32_random_t* gen, uint32_t* data, size_t dataSize);

