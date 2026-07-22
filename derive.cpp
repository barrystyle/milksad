#include <iostream>
#include <iomanip>
#include <cstring>
#include <openssl/hmac.h>
#include <secp256k1.h>

#include "base58.h"

std::vector<uint8_t> hex_to_vec(const std::string &hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size()/2);
    for (size_t i=0;i<hex.size();i+=2){
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i,2);
        ss >> byte;
        out.push_back((uint8_t)byte);
    }
    return out;
}

void ser32(uint32_t i, uint8_t out[4]) {
    out[0] = (uint8_t)((i >> 24) & 0xFF);
    out[1] = (uint8_t)((i >> 16) & 0xFF);
    out[2] = (uint8_t)((i >> 8) & 0xFF);
    out[3] = (uint8_t)(i & 0xFF);
}


void hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen, uint8_t out64[64]) {
    unsigned int len = 64;
    HMAC(EVP_sha512(), key, (int)keylen, data, datalen, out64, &len);
}

std::vector<std::pair<uint32_t,bool>> parse_path(const std::string &path) {
    std::vector<std::pair<uint32_t,bool>> comps;
    if (path.size() == 0) return comps;
    std::string p = path;
    if (p[0] == 'm') {
        if (p.size() > 1 && p[1] == '/') p = p.substr(2);
        else if (p.size() == 1) return comps;
    }
    std::istringstream ss(p);
    std::string token;
    while (std::getline(ss, token, '/')) {
        if (token.size() == 0) continue;
        bool hardened = false;
        if (token.back() == '\'' || token.back() == 'h' || token.back() == 'H') {
            hardened = true;
            token = token.substr(0, token.size()-1);
        }
        uint32_t idx = (uint32_t)std::stoul(token);
        comps.push_back({ idx, hardened });
    }
    return comps;
}

bool pubkey_from_priv(secp256k1_context* ctx, const uint8_t priv[32], uint8_t *out_pub, size_t &outlen, bool compressed) {
    if (!secp256k1_ec_seckey_verify(ctx, priv)) return false;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(ctx, &pk, priv)) return false;
    outlen = compressed ? 33 : 65;
    unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
    if (!secp256k1_ec_pubkey_serialize(ctx, out_pub, &outlen, &pk, flags)) return false;
    return true;
}

BIGNUM* bn_from_32(const uint8_t in[32]) {
    return BN_bin2bn(in, 32, nullptr);
}

bool bn_to_32(const BIGNUM *bn, uint8_t out[32]) {
    int needed = BN_num_bytes(bn);
    if (needed > 32) return false;
    unsigned char tmp[32] = {0};
    int bytes = BN_bn2bin(bn, tmp + (32 - needed)); // write right-aligned
    memcpy(out, tmp, 32);
    return true;
}

bool master_from_seed(const uint8_t *seed, size_t seedlen, uint8_t master_priv[32], uint8_t master_chain[32]) {
    uint8_t I[64];
    hmac_sha512((const uint8_t*)"Bitcoin seed", 12, seed, seedlen, I);
    memcpy(master_priv, I, 32);
    memcpy(master_chain, I+32, 32);
    return true;
}

bool ckd_priv(secp256k1_context* ctx, const uint8_t parent_priv[32], const uint8_t parent_chain[32], uint32_t idx, bool hardened, uint8_t child_priv[32], uint8_t child_chain[32]) {
    uint8_t data[1 + 33 + 4 + 32]; // max
    size_t datalen = 0;

    uint32_t use_idx = idx | (hardened ? 0x80000000u : 0u);
    if (hardened) {
        // data = 0x00 || ser256(k_par) || ser32(i)
        data[0] = 0x00;
        memcpy(data+1, parent_priv, 32);
        ser32(use_idx, data+1+32);
        datalen = 1 + 32 + 4;
        // HMAC key = parent_chain
    } else {
        // data = serP(point(k_par)) || ser32(i)
        uint8_t parent_pub[65];
        size_t parent_pub_len = 65;
        if (!pubkey_from_priv(ctx, parent_priv, parent_pub, parent_pub_len, true)) return false;
        memcpy(data, parent_pub, parent_pub_len);
        ser32(use_idx, data + parent_pub_len);
        datalen = parent_pub_len + 4;
    }

    uint8_t I[64];
    hmac_sha512(parent_chain, 32, data, datalen, I);
    const uint8_t *IL = I;
    const uint8_t *IR = I + 32;

    // parse IL as integer, add to parent_priv, mod n
    BIGNUM *bn_IL = bn_from_32(IL);
    BIGNUM *bn_kpar = bn_from_32(parent_priv);
    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_IL || !bn_kpar || !bn_ctx) { BN_free(bn_IL); BN_free(bn_kpar); BN_CTX_free(bn_ctx); return false; }

    // curve order n
    BIGNUM *bn_n = BN_new();
    BN_hex2bn(&bn_n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    // If IL >= n -> invalid
    if (BN_cmp(bn_IL, bn_n) >= 0) {
        BN_free(bn_IL); BN_free(bn_kpar); BN_free(bn_n); BN_CTX_free(bn_ctx);
        return false; // per BIP32: proceed to next index in production code
    }

    BIGNUM *bn_child = BN_new();
    BN_mod_add(bn_child, bn_IL, bn_kpar, bn_n, bn_ctx); // (IL + kpar) mod n

    // child == 0 -> invalid
    if (BN_is_zero(bn_child)) {
        BN_free(bn_IL); BN_free(bn_kpar); BN_free(bn_child); BN_free(bn_n); BN_CTX_free(bn_ctx);
        return false;
    }

    // convert child to 32 bytes
    if (!bn_to_32(bn_child, child_priv)) {
        BN_free(bn_IL); BN_free(bn_kpar); BN_free(bn_child); BN_free(bn_n); BN_CTX_free(bn_ctx);
        return false;
    }

    // chain = IR
    memcpy(child_chain, IR, 32);

    BN_free(bn_IL); BN_free(bn_kpar); BN_free(bn_child); BN_free(bn_n); BN_CTX_free(bn_ctx);
    return true;
}

bool derive_path(secp256k1_context* ctx, const uint8_t seed[], size_t seedlen, const std::string &path, uint8_t out_priv[32], uint8_t out_chain[32]) {
    uint8_t master_priv[32], master_chain[32];
    if (!master_from_seed(seed, seedlen, master_priv, master_chain)) return false;

    // if path is "m" or empty -> master
    auto comps = parse_path(path);
    if (comps.empty()) {
        memcpy(out_priv, master_priv, 32);
        memcpy(out_chain, master_chain, 32);
        return true;
    }

    uint8_t cur_priv[32], cur_chain[32];
    memcpy(cur_priv, master_priv, 32);
    memcpy(cur_chain, master_chain, 32);

    for (auto &c : comps) {
        uint32_t idx = c.first;
        bool hardened = c.second;
        uint8_t child_priv[32], child_chain[32];
        if (!ckd_priv(ctx, cur_priv, cur_chain, idx, hardened, child_priv, child_chain)) {
            std::cerr << "Derivation failed at index " << idx << (hardened ? " (hardened)" : "") << "\n";
            return false;
        }
        memcpy(cur_priv, child_priv, 32);
        memcpy(cur_chain, child_chain, 32);
    }

    memcpy(out_priv, cur_priv, 32);
    memcpy(out_chain, cur_chain, 32);
    return true;
}

bool derive_keys_p2pkh(std::vector<uint8_t> seed_vec, const std::string path, pairSet& result) {

    // create secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    uint8_t final_priv[32], final_chain[32];
    if (!derive_path(ctx, seed_vec.data(), seed_vec.size(), path, final_priv, final_chain)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // generate corresponding compressed and uncompressed pubkeys
    uint8_t pub_comp[33]; size_t pub_comp_len = 33;
    uint8_t pub_uncomp[65]; size_t pub_uncomp_len = 65;

    //compressed p2pkh
    if (!pubkey_from_priv(ctx, final_priv, pub_comp, pub_comp_len, true)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    result.wif_compressed_pubkey = p2pkh_from_pub(pub_comp, pub_comp_len);

    secp256k1_context_destroy(ctx);
    return true;
}

bool derive_keys_p2sh_p2wpkh(std::vector<uint8_t> seed_vec, const std::string path, pairSet& result) {

    // create secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    uint8_t final_priv[32], final_chain[32];
    if (!derive_path(ctx, seed_vec.data(), seed_vec.size(), path, final_priv, final_chain)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // generate corresponding compressed and uncompressed pubkeys
    uint8_t pub_comp[33]; size_t pub_comp_len = 33;
    uint8_t pub_uncomp[65]; size_t pub_uncomp_len = 65;

    //compressed p2sh_p2wpkh
    if (!pubkey_from_priv(ctx, final_priv, pub_comp, pub_comp_len, true)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    result.wif_compressed_pubkey = p2sh_p2wpkh_from_pub(pub_comp, pub_comp_len);

    secp256k1_context_destroy(ctx);
    return true;
}

bool derive_keys_p2wpkh(std::vector<uint8_t> seed_vec, const std::string path, pairSet& result) {

    // create secp256k1 context
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    uint8_t final_priv[32], final_chain[32];
    if (!derive_path(ctx, seed_vec.data(), seed_vec.size(), path, final_priv, final_chain)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    // generate corresponding compressed and uncompressed pubkeys
    uint8_t pub_comp[33]; size_t pub_comp_len = 33;
    uint8_t pub_uncomp[65]; size_t pub_uncomp_len = 65;

    //compressed p2wpkh
    if (!pubkey_from_priv(ctx, final_priv, pub_comp, pub_comp_len, true)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    result.wif_compressed_pubkey = p2wpkh_from_pub(pub_comp, pub_comp_len);

    secp256k1_context_destroy(ctx);
    return true;
}
