#pragma once

#include "nemTypes.h"
#include "PcgRandom.h"
#include <array>

class KeyGenerator
{
public:
	void generate(nem::Key& privateKey, nem::Key& publicKey);	
	static int derivePublicKey(const nem::Key& priv, nem::Key& pub);

private:
	PcgRandom m_pcgRandom;
};
