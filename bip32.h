#ifndef BIP32_H
#define BIP32_H

#include <string.h>
#include <string>
#include <vector>

void entropy_to_mnemonic(char* entropy, int bitlen, std::string& mnemonic);
void mnemonic_to_seed(std::string& phrase, std::string& seed_);

#endif // BIP32_H
