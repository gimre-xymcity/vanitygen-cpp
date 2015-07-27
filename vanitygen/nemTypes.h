#pragma once

#include <array>
#include <stdint.h>

namespace nem
{
	typedef std::array<uint8_t, 64> Signature;
	typedef std::array<uint8_t, 32> Key;
}