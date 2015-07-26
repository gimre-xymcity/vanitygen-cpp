#include "utils.h"

void randombytes(unsigned char* _data, size_t dataSize)
{
	uint32_t* data = (uint32_t*)_data;
	dataSize /= 4;
	for (size_t i = 0; i < dataSize; ++i)
		data[i] = pcg32_random();
}

void fill(pcg32_random_t* gen, uint32_t* data, size_t dataSize)
{
	for (size_t i = 0; i < dataSize; ++i)
		data[i] = pcg32_random_r(gen);
}
