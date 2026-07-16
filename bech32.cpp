#include <string>
#include <vector>
#include <stdint.h>

// Bech32 checksum constants (BIP-173)
static const uint32_t BECH32_GEN[5] = {
    0x3b6a57b2,
    0x26508e6d,
    0x1ea119fa,
    0x3d4233dd,
    0x2a1462b3
};

static inline uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint8_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            chk ^= ((top >> i) & 1) ? BECH32_GEN[i] : 0;
        }
    }
    return chk;
}

static inline std::vector<uint8_t> bech32_hrp_expand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);

    for (char c : hrp) ret.push_back(c >> 5);
    ret.push_back(0);
    for (char c : hrp) ret.push_back(c & 0x1f);

    return ret;
}

static inline std::string bech32_create_checksum(const std::string& hrp,
                                                 const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = bech32_hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);

    uint32_t mod = bech32_polymod(values) ^ 1;

    std::string ret;
    ret.resize(6);

    static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    for (int i = 0; i < 6; ++i) {
        ret[i] = CHARSET[(mod >> (5 * (5 - i))) & 0x1f];
    }
    return ret;
}

std::string bech32_encode(const std::string& hrp,
                          const std::vector<uint8_t>& data)
{
    static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Build output string: hrp + "1" + encoded data + checksum
    std::string ret = hrp + "1";

    for (uint8_t v : data) {
        if (v > 31) return ""; // invalid 5-bit value
        ret.push_back(CHARSET[v]);
    }

    std::string checksum = bech32_create_checksum(hrp, data);
    ret += checksum;

    return ret;
}
