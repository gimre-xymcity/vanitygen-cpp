#include "PcgRandom.h"

#include <time.h>

PcgRandom::PcgRandom()
{
	uint64_t seed[2];

	seed[0] = time(0);
	seed[1] = 0x696f3104;
	pcg32_srandom_r(&m_gen, seed[0], seed[1]);
	for (int i = 0; i < 1000; ++i) {
		pcg32_random_r(&m_gen);
	}
}

void PcgRandom::fill(uint32_t* data, size_t dataSize)
{
	for (size_t i = 0; i < dataSize; ++i)
		data[i] = pcg32_random_r(&m_gen);
}
