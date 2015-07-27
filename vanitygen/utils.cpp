#include "utils.h"

void randombytes(unsigned char* _data, size_t dataSize)
{
	uint32_t* data = (uint32_t*)_data;
	dataSize /= 4;
	for (size_t i = 0; i < dataSize; ++i)
		data[i] = pcg32_random();
}
