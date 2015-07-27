#include "KeyGenerator.h"

#include "ref10/ge.h"
#include "ref10/sha512.h"

void KeyGenerator::generate(nem::Key& privateKey, nem::Key& publicKey)
{
	m_pcgRandom.fill((uint32_t*)privateKey.data(), privateKey.size() / sizeof(uint32_t));

	derivePublicKey(privateKey, publicKey);
}

int KeyGenerator::derivePublicKey(const nem::Key& priv, nem::Key& pub)
{
	unsigned char h[64];
	ge_p3 A;

	crypto_hash_sha512(h, priv.data(), 32);

	h[0] &= 0xf8;
	h[31] &= 0x7f;
	h[31] |= 0x40;

	ge_scalarmult_base(&A, h);
	ge_p3_tobytes(pub.data(), &A);

	return 0;
}
