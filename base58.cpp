#include "base58.h"

// --- SHA helpers ---
std::vector<uint8_t> sha256_vec(const uint8_t *data, size_t len) {
    std::vector<uint8_t> out(32);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out.data(), &ctx);
    return out;
}
std::vector<uint8_t> double_sha256_vec(const uint8_t *data, size_t len) {
    auto first = sha256_vec(data, len);
    auto second = sha256_vec(first.data(), first.size());
    return second;
}

// HASH160 = RIPEMD160(SHA256(data))
std::vector<uint8_t> hash160(const uint8_t *data, size_t len) {
    auto sha = sha256_vec(data, len);
    std::vector<uint8_t> out(20);
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, sha.data(), sha.size());
    RIPEMD160_Final(out.data(), &ctx);
    return out;
}

// --- Base58 / Base58Check ---
// alphabet
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string base58_encode(const std::vector<uint8_t> &in) {
    // count leading zeros
    size_t zeros = 0;
    while (zeros < in.size() && in[zeros] == 0) ++zeros;

    // convert to big integer (base58) using digit-array method
    std::vector<unsigned int> digits;
    digits.reserve(in.size()*2);
    digits.push_back(0);

    for (size_t i = zeros; i < in.size(); ++i) {
        unsigned int carry = in[i];
        for (size_t j = 0; j < digits.size(); ++j) {
            unsigned long long val = (unsigned long long)digits[j] * 256ULL + carry;
            digits[j] = (unsigned int)(val % 58ULL);
            carry = (unsigned int)(val / 58ULL);
        }
        while (carry) {
            digits.push_back((unsigned int)(carry % 58ULL));
            carry /= 58ULL;
        }
    }

    // produce string (reverse digits)
    std::string result;
    result.reserve(zeros + digits.size());
    // leading zeros -> '1'
    for (size_t i = 0; i < zeros; ++i) result.push_back('1');
    // convert digits in reverse
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) result.push_back(BASE58_ALPHABET[*it]);
    return result;
}

// Base58Check: payload -> Base58Check(version + payload)
std::string base58check_encode(uint8_t version, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> data;
    data.reserve(1 + payload.size() + 4);
    data.push_back(version);
    data.insert(data.end(), payload.begin(), payload.end());
    auto checksum_full = double_sha256_vec(data.data(), data.size());
    data.insert(data.end(), checksum_full.begin(), checksum_full.begin()+4);
    return base58_encode(data);
}

// --- P2PKH address from public key (compressed or uncompressed) ---
// version byte 0x00 for mainnet P2PKH
std::string p2pkh_from_pub(const uint8_t *pub, size_t pub_len) {
    auto h160 = hash160(pub, pub_len); // 20 bytes
    return base58check_encode(0x00, h160);
}

std::string p2sh_p2wpkh_from_pub(const uint8_t *pub, size_t pub_len)
{
    std::vector<uint8_t> h160 = hash160(pub, pub_len); // 20 bytes
    uint8_t redeem[22];
    redeem[0] = 0x00; // OP_0
    redeem[1] = 0x14; // PUSH 20 bytes
    memcpy(redeem + 2, h160.data(), 20);
    std::vector<uint8_t> redeem_h160 = hash160(redeem, sizeof(redeem));
    return base58check_encode(0x05, redeem_h160);
}

std::string p2wpkh_from_pub(const uint8_t *pub, size_t pub_len, const std::string& hrp)
{
    std::vector<uint8_t> h160 = hash160(pub, pub_len); // 20 bytes
    std::vector<uint8_t> data;
    data.push_back(0x00); // witness version 0
    int acc = 0, bits = 0;
    for (uint8_t b : h160) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data.push_back((acc >> bits) & 0x1F);
        }
    }
    if (bits > 0) {
        data.push_back((acc << (5 - bits)) & 0x1F);
    }
    return bech32_encode(hrp, data);
}
