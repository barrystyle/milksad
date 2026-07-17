#include <illbloom.h>

static double js_to_uint32(double x) {
    if (!std::isfinite(x)) return 0.0;
    double posInt = std::trunc(x);
    double m = std::fmod(posInt, 4294967296.0); // mod 2^32
    if (m < 0) m += 4294967296.0;
    return m; // in [0, 2^32)
}

static double js_to_int32(double x) {
    double u = js_to_uint32(x);
    if (u >= 2147483648.0) u -= 4294967296.0;
    return u; // in [-2^31, 2^31 - 1]
}

static inline uint32_t as_u32(double int32val) {
    int32_t s = (int32_t)int32val;
    return (uint32_t)s;
}

static double js_and(double a, double b) {
    uint32_t au = as_u32(js_to_int32(a));
    uint32_t bu = as_u32(js_to_int32(b));
    int32_t r = (int32_t)(au & bu);
    return (double)r;
}

static double js_shl(double a, int n) {
    uint32_t au = as_u32(js_to_int32(a));
    uint32_t r = au << (n & 31);
    return (double)(int32_t)r;
}

static double js_shr(double a, int n) {
    int32_t ai = (int32_t)as_u32(js_to_int32(a));
    int32_t r = ai >> (n & 31);
    return (double)r;
}

static double js_or0(double a) {
    return js_to_int32(a);
}

struct MwcState {
    double m_z;
    double m_w;
};

static double mwc_step(MwcState &st, double mockedRandom) {
    st.m_z = js_and(0x9069 * js_and(st.m_z, 0xFFFF) + js_shr(st.m_z, 0x10), 0xffffffffLL * 1.0);
    st.m_w = js_and(0x4650 * js_and(st.m_w, 0xFFFF) + js_shr(st.m_w, 0x10), 4294967295.0);
    double result = js_and(js_shl(st.m_z, 0x10) + st.m_w, 4294967295.0);
    result /= 4294967296.0; // 0x100000000
    result += 0.5;
    double sign = (mockedRandom > 0.5) ? 1.0 : -1.0;
    return result * sign;
}

static std::string cryptojs_random_hex(int nBytes, double mockedRandom) {
    std::vector<uint32_t> words;
    double rcache = 0.0;
    bool haveRcache = false;

    for (int i = 0; i < nBytes; i += 4) {
        double seedVal = (haveRcache && rcache != 0.0) ? rcache : mockedRandom;
        double m_w_init = seedVal * 4294967296.0;
        MwcState st;
        st.m_z = 0x3ade68b1;
        st.m_w = m_w_init;

        double v1 = mwc_step(st, mockedRandom);
        rcache = v1 * 0x3ade67b7;
        haveRcache = true;

        double v2 = mwc_step(st, mockedRandom);
        double word = js_or0(v2 * 4294967296.0);
        words.push_back(as_u32(word));
    }

    std::string hex;
    hex.reserve(nBytes * 2);
    char buf[9];
    int bytesLeft = nBytes;
    for (uint32_t w : words) {
        std::snprintf(buf, sizeof(buf), "%08x", w);
        int take = bytesLeft >= 4 ? 8 : bytesLeft * 2;
        hex.append(buf, take);
        bytesLeft -= 4;
    }
    return hex;
}

std::string emulate_cryptojs_wordarray(uint32_t increment) {
    double mockedRandom = (double)increment / 4294967296.0;
    return cryptojs_random_hex(16, mockedRandom);
}
