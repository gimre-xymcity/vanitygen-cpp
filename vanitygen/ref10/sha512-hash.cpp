#include "sha512.h"

#include "../sha3/KeccakNISTInterface.h"

int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
	hashState _hctx, *hctx = &_hctx;
	Init(hctx, 512);
	Update(hctx, in, inlen * 8);
	Final(hctx, out);

	return 0;
}
