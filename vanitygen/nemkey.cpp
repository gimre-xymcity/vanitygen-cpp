#include "ref10/ge.h"
#include "ref10/sha512.h"

int crypto_sign_keypair(const unsigned char *priv, unsigned char *pub)
{
	unsigned char h[64];
	ge_p3 A;

	crypto_hash_sha512(h, priv, 32);

	h[0] &= 0xf8;
	h[31] &= 0x7f;
	h[31] |= 0x40;

	ge_scalarmult_base(&A, h);
	ge_p3_tobytes(pub, &A);

	return 0;
}