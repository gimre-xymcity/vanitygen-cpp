#pragma once

#include "pcg/pcg_basic.h"

#include <stdint.h>

class PcgRandom
{
public:
	PcgRandom();
	void fill(uint32_t* data, size_t dataSize);

private:
	pcg32_random_t m_gen;
};