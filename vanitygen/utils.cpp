#include "utils.h"

#include <iterator>
#include <string>

void randombytes(unsigned char* _data, size_t dataSize)
{
	uint32_t* data = (uint32_t*)_data;
	dataSize /= 4;
	for (size_t i = 0; i < dataSize; ++i)
		data[i] = pcg32_random();
}

uint8_t strToVal(const char c) {
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= '0' && c <= '9') return c - '0';
	return 0;
}

uint8_t strToByte(const char* twoBytes) {
	return (strToVal(twoBytes[0]) << 4) | strToVal(twoBytes[1]);
}

// NOTE: this reverses the format of private key...
void inputStringToPrivateKey(const std::string& privString, uint8_t* privateKey) {
	if (privString.size() != 64) {
		throw std::runtime_error("private key in input file must have 64 characters");
	}

	for (size_t i = 0; i < privString.size(); i += 2) {
		privateKey[31 - i / 2] = strToByte(&privString[i]);
	}
}

void inputStringToData(const std::string& dataString, size_t requiredSize, uint8_t* dataOutput) {
	if (dataString.size() != requiredSize) {
		throw std::runtime_error("field in input file must have "+std::to_string(requiredSize) + " characters");
	}

	for (size_t i = 0; i < dataString.size(); i += 2) {
		dataOutput[i / 2] = strToByte(&dataString[i]);
	}
}

class Line : public std::string
{
	friend std::istream& operator>>(std::istream& is, Line& line)
	{
		return std::getline(is, line);
	}
};

void forLineInFile(std::istream& inputFile, std::function<bool(const std::string&)> callback)
{
	typedef std::istream_iterator<Line> LineIt;

	for (auto it = LineIt(inputFile), _it = LineIt(); it != _it; ++it) {
		if (!callback(*it)) {
			break;
		}
	}
}
