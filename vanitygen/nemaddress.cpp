#include "nemaddress.h"

#include "base32/base32.h"
#include "sha3/KeccakNISTInterface.h"

void computeRIPEMD160(const void *_message, uint32_t length, uint8_t hashcode[20]);

void calculateAddress(const uint8_t* data, size_t size, char* nemAddress)
{
	unsigned char sha3result[32];

	hashState _hctx, *hctx = &_hctx;
	Init(hctx, 256);
	Update(hctx, data, size * 8);
	Final(hctx, sha3result);

	unsigned char r160result[25];
	computeRIPEMD160(sha3result, 32, r160result + 1);
	r160result[0] = 0x68;

	Init(hctx, 256);
	Update(hctx, r160result, 21 * 8);
	Final(hctx, sha3result);

	*(uint32_t*)(r160result + 21) = *(uint32_t*)(sha3result);

	base32_encode(r160result, 25, (unsigned char*)nemAddress);
	nemAddress[40] = 0;
}