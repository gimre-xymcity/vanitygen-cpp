#pragma once

#include "nemTypes.h"
#include "KeyPair.h"

class DsaSigner
{
public:
	/***
	 * Returns true if signature has been calculated correctly, false if generated signature is not canonical
	 * in such case this function should be called again.
	 */
	static bool sign(const KeyPair& keyPair, const uint8_t* data, size_t dataSize, nem::Signature& signature);

private:

};