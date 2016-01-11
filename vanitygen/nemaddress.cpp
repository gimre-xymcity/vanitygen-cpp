#include "nemaddress.h"

#include "base32/base32.h"
#include "sha3/KeccakHash.h"

void computeRIPEMD160(const void *_message, uint32_t length, uint8_t hashcode[20]);

void calculateAddress(const uint8_t* data, size_t size, char* nemAddress)
{
	unsigned char sha3result[32];

	Keccak_HashInstance _hctx, *hctx = &_hctx;
	Keccak_HashInitialize_SHA3_256(hctx);
	Keccak_HashUpdate(hctx, data, size * 8);
	Keccak_HashSqueeze(hctx, sha3result, 256);

	unsigned char r160result[25];
	computeRIPEMD160(sha3result, 32, r160result + 1);
	r160result[0] = 0x68;

	Keccak_HashInitialize_SHA3_256(hctx);
	Keccak_HashUpdate(hctx, r160result, 21 * 8);
	Keccak_HashSqueeze(hctx, sha3result, 256);

	*(uint32_t*)(r160result + 21) = *(uint32_t*)(sha3result);

	base32_encode(r160result, 25, (unsigned char*)nemAddress);
	nemAddress[40] = 0;
}