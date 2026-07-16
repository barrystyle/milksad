// Copyright (c) 2023 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>
#include <string>

#include <bip39.h>
#include <util.h>

#include "base58.h"

void entropy_to_mnemonic(char* entropy, int bitlen, std::string& mnemonic)
{
    std::vector<uint8_t> entropy_;
    for (int i=0; i<bitlen/8; i++) {
        entropy_.push_back(entropy[i]);
    }
    mnemonic = CMnemonic::FromData(entropy_, bitlen/8);
}

void mnemonic_to_seed(std::string& phrase, std::string& seed_)
{
    char bip39seed[512];
    std::vector<uint8_t> seed;
    memset(bip39seed, 0, sizeof(bip39seed));
    CMnemonic::ToSeed(phrase, std::string(""), seed);
    for (int i = 0; i < seed.size(); i++) {
        sprintf(bip39seed + (i * 2), "%02hhx", seed[i]);
    }
    seed_ = std::string(bip39seed);
}
