#ifndef DERIVE_H
#define DERIVE_H

#include <string.h>
#include <string>
#include <vector>

std::vector<uint8_t> hex_to_vec(const std::string &hex);
bool derive_keys_p2pkh(std::vector<uint8_t> seed_vec, std::string path, pairSet& result);
bool derive_keys_p2sh_p2wpkh(std::vector<uint8_t> seed_vec, std::string path, pairSet& result);
bool derive_keys_p2wpkh(std::vector<uint8_t> seed_vec, std::string path, pairSet& result);

#endif // DERIVE_H
