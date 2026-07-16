#ifndef BASE58_H
#define BASE58_H

#include <array>
#include <string>
#include <vector>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

struct pairSet {
   std::string wif_compressed_pubkey;
   std::string wif_compressed_privkey;
   std::string wif_uncompressed_pubkey;
   std::string wif_uncompressed_privkey;
};

std::vector<uint8_t> sha256_vec(const uint8_t *data, size_t len);
std::vector<uint8_t> double_sha256_vec(const uint8_t *data, size_t len);
std::vector<uint8_t> hash160(const uint8_t *data, size_t len);
std::string base58_encode(const std::vector<uint8_t> &in);
std::string base58check_encode(uint8_t version, const std::vector<uint8_t> &payload);
std::string wif_from_priv(const uint8_t priv[32], bool compressed);
std::string p2pkh_from_pub(const uint8_t *pub, size_t pub_len);
std::string p2sh_p2wpkh_from_pub(const uint8_t *pub, size_t pub_len);
std::string p2wpkh_from_pub(const uint8_t *pub, size_t pub_len, const std::string& hrp = "bc");

std::string bech32_encode(const std::string& hrp,
                          const std::vector<uint8_t>& data);
#endif // BASE58_H
