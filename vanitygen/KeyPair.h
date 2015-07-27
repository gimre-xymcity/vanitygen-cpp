#pragma once

#include "KeyGenerator.h"

#include <algorithm>
#include <array>

class KeyPair
{
public:
	typedef KeyGenerator::Key Key;

	KeyPair(KeyGenerator& keyGenerator)
	{
		keyGenerator.generate(m_privateKey, m_publicKey);
	}

	KeyPair(const Key& privateKey)
	{
		m_privateKey = privateKey;
		KeyGenerator::derivePublicKey(m_privateKey, m_publicKey);
	}

	const Key& getPublicKey() const {
		return m_publicKey;
	}

	const Key& getPrivateKey() const {
		return m_privateKey;
	}

private:
	Key m_privateKey;
	Key m_publicKey;
};