#pragma once

#include "pcg/pcg_basic.h"

#include <functional>
#include <istream>

#include <stdint.h>


void randombytes(unsigned char* _data, size_t dataSize);

void inputStringToPrivateKey(const std::string& privString, uint8_t* privateKey);
void inputStringToPublicKey(const std::string& pubString, uint8_t* publicKey);
void forLineInFile(std::istream& inputFile, std::function<void(const std::string&)> callback);