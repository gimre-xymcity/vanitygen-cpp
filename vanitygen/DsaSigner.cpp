#include "DsaSigner.h"

#include "ref10/ge.h"
#include "ref10/sha512.h"
#include "ref10/sc.h"
#include "sha3/KeccakNISTInterface.h"

#ifdef _MSC_VER
#define RESTRICT __restrict
#else
#define RESTRICT __restrict__
#endif

bool DsaSigner::sign(const KeyPair& keyPair, const uint8_t* data, size_t dataSize, nem::Signature& signature)
{
	hashState hctx;
	uint8_t privHash[64];
	uint8_t r[64];
	uint8_t h[64];

	uint8_t *RESTRICT encodedR = signature.data();
	uint8_t *RESTRICT encodedS = signature.data() + 32;

	crypto_hash_sha512(privHash, keyPair.getPrivateKey().data(), 32);

	privHash[0] &= 0xf8;
	privHash[31] &= 0x7f;
	privHash[31] |= 0x40;

	
	Init(&hctx, 512);
	Update(&hctx, privHash + 32, 32 * 8);
	Update(&hctx, data, dataSize * 8);
	Final(&hctx, r);

	ge_p3 rMulBase;
	sc_reduce(r);
	ge_scalarmult_base(&rMulBase, r);
	ge_p3_tobytes(encodedR, &rMulBase);

	// encodedR || public || data

	Init(&hctx, 512);
	Update(&hctx, encodedR, 32 * 8);
	Update(&hctx, keyPair.getPublicKey().data(), 32 * 8);
	Update(&hctx, data, dataSize * 8);
	Final(&hctx, h);

	sc_reduce(h);
	sc_muladd(encodedS, h, privHash, r);

	// check if signature is canonical
	memset(r + 32, 0, 32);
	if (memcmp(encodedS, r + 32, 32) == 0) {
		return false;
	}
	memcpy(r, encodedS, 32);
	sc_reduce(r);

	return 0 == memcmp(r, encodedS, 32);
}
