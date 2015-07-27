#pragma once

#include "nemTypes.h"
#include "KeyPair.h"

class DsaSigner
{
public:
	static void sign(const KeyPair& keyPair, const uint8_t* data, size_t dataSize, nem::Signature& signature);

private:

};