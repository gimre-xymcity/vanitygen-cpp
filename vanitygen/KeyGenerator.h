#pragma once

#include "PcgRandom.h"
#include <array>

class KeyGenerator
{
public:
	typedef std::array<uint8_t, 32> Key;

	void generate(Key& privateKey, Key& publicKey);	
	static int derivePublicKey(const Key& priv, Key& pub);

private:
	PcgRandom m_pcgRandom;
};
