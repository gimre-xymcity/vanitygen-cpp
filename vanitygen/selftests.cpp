#include "nemkey.h"

#include "nemaddress.h"
#include "cppformat/format.h"
#include "sha3/KeccakNISTInterface.h"

#define erro(strfmt, ...) do { fmt::print(" [!] "); fmt::print(strfmt, __VA_ARGS__); fmt::print("\n"); } while(0)
#define succ(strfmt, ...) do { fmt::print(" [+] "); fmt::print(strfmt, __VA_ARGS__); fmt::print("\n"); } while(0)

static bool sha3selfTest()
{
	const unsigned char data[] = "\xc5\x24\x77\x38\xc3\xa5\x10\xfb\x6c\x11\x41\x33\x31\xd8\xa4\x77\x64\xf6\xe7\x8f\xfc\xdb\x02\xb6\x87\x8d\x5d\xd3\xb7\x7f\x38\xed";
	const unsigned char expected[] = "\x70\xc9\xdc\xf6\x96\xb2\xad\x92\xdb\xb9\xb5\x2c\xeb\x33\xec\x0e\xda\x5b\xfd\xb7\x05\x2d\xf4\x91\x4c\x09\x19\xca\xdd\xb9\xdf\xcf";

	unsigned char result[32];

	hashState _hctx, *hctx = &_hctx;
	Init(hctx, 256);
	Update(hctx, data, (sizeof(data) - 1) * 8);
	Final(hctx, result);

	if (memcmp(result, expected, 32)) {
		erro("SELF TEST (sha3): failed");
		return false;
	}
	succ("SELF TEST (sha3): OK");

	return true;
}

static bool sha3512selfTest()
{
	const unsigned char data[] = "\xf1\x8e\xfd\x04\x2a\xf9\x3b\x0e\xe1\x24\xa2\x0b\x73\x95\x71\xb0\xed\x66\xe7\x6a\xe3\xa1\x11\xf0\x02\x97\xdb\x30\x5e\xba\xe7\xb2";
	const unsigned char expected[] = "\x86\x29\x2f\x63\xfc\x79\xc3\x4f\x2a\xf7\x39\x2e\x27\xf0\x79\x5f\xcd\xce\x63\x78\x25\x15\x55\xc7\x41\xb5\x7f\x2b\xe7\x08\xdf\x28\x50\xa9\xb6\xa3\xa2\xd9\x2c\xb4\xac\x80\xdc\x64\xd7\xbd\xc8\xd4\x38\x90\xc6\x34\x62\x87\x51\xef\x9e\xf9\x63\x6e\xf8\xbf\xaf\x4e";

	unsigned char result[64];

	hashState _hctx, *hctx = &_hctx;
	Init(hctx, 512);
	Update(hctx, data, (sizeof(data) - 1) * 8);
	Final(hctx, result);

	if (memcmp(result, expected, 64)) {
		erro("SELF TEST (sha3-512): failed");
		return false;
	}
	succ("SELF TEST (sha3-512): OK");
	return true;
}

void computeRIPEMD160(const void *_message, uint32_t length, uint8_t hashcode[20]);

static bool ripemd160selfTest()
{
	const unsigned char data[] = "\x70\xc9\xdc\xf6\x96\xb2\xad\x92\xdb\xb9\xb5\x2c\xeb\x33\xec\x0e\xda\x5b\xfd\xb7\x05\x2d\xf4\x91\x4c\x09\x19\xca\xdd\xb9\xdf\xcf";
	const unsigned char expected[] = "\x1f\x14\x2c\x5e\xa4\x85\x30\x63\xed\x6d\xc3\xc1\x3a\xaa\x82\x57\xcd\x7d\xaf\x11";

	unsigned char result[20];

	computeRIPEMD160(data, sizeof(data) - 1, result);


	if (memcmp(result, expected, 20)) {
		erro("SELF TEST (ripemd160): failed");
		return false;
	}
	succ("SELF TEST (ripemd160): OK");
	return true;
}

static bool addressSelfTest()
{
	const unsigned char data[] = "\xc5\x24\x77\x38\xc3\xa5\x10\xfb\x6c\x11\x41\x33\x31\xd8\xa4\x77\x64\xf6\xe7\x8f\xfc\xdb\x02\xb6\x87\x8d\x5d\xd3\xb7\x7f\x38\xed";
	char address[41];
	calculateAddress(data, sizeof(data) - 1, address);


	if (strcmp(address, "NAPRILC6USCTAY7NNXB4COVKQJL427NPCEERGKS6")) {
		erro("SELF TEST (address): failed");
		return false;
	}
	succ("SELF TEST (address): OK");
	return true;
}

static bool keypairSelfTest()
{
	// reversed
	unsigned char data[] = "\xf1\x8e\xfd\x04\x2a\xf9\x3b\x0e\xe1\x24\xa2\x0b\x73\x95\x71\xb0\xed\x66\xe7\x6a\xe3\xa1\x11\xf0\x02\x97\xdb\x30\x5e\xba\xe7\xb2";
	unsigned char result[64];

	if (crypto_sign_keypair(data, result)) {
		return false;
	}

	if (memcmp(result, "\xc5\x24\x77\x38\xc3\xa5\x10\xfb\x6c\x11\x41\x33\x31\xd8\xa4\x77\x64\xf6\xe7\x8f\xfc\xdb\x02\xb6\x87\x8d\x5d\xd3\xb7\x7f\x38\xed", 32)) {
		erro("SELF TEST (keypair): failed");
		return false;
	}
	succ("SELF TEST (keypair): OK");
	return true;
}

bool selfTest()
{
	return sha3selfTest() && sha3512selfTest() && ripemd160selfTest() && addressSelfTest() && keypairSelfTest();
}