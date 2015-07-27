#pragma once

#include "KeyGenerator.h"

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