#pragma once

#include "pcg/pcg_basic.h"

#include <functional>
#include <istream>

#include <stdint.h>


void randombytes(unsigned char* _data, size_t dataSize);

void inputStringToPrivateKey(const std::string& privString, uint8_t* privateKey);
void inputStringToData(const std::string& dataString, size_t requiredSize, uint8_t* dataOutput);
void forLineInFile(std::istream& inputFile, std::function<bool(const std::string&)> callback);