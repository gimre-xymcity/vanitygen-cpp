#pragma once

#include "KeyGenerator.h"
#include "DsaSigner.h"

#include <algorithm>
#include <array>

class KeyPair
{
public:
	KeyPair(KeyGenerator& keyGenerator)
	{
		keyGenerator.generate(m_privateKey, m_publicKey);
	}

	KeyPair(const nem::Key& privateKey)
	{
		m_privateKey = privateKey;
		KeyGenerator::derivePublicKey(m_privateKey, m_publicKey);
	}

	void sign(const uint8_t* data, size_t dataSize, nem::Signature& signature)
	{
		DsaSigner::sign(m_privateKey, data, dataSize, signature);
	}

	const nem::Key& getPublicKey() const {
		return m_publicKey;
	}

	const nem::Key& getPrivateKey() const {
		return m_privateKey;
	}

private:
	nem::Key m_privateKey;
	nem::Key m_publicKey;
};