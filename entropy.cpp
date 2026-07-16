#include <random>
#include <string.h>

void get_entropy(uint32_t seed_value, int offset, char *data) {
    std::mt19937 engine(seed_value);
    std::vector<uint8_t> entropy(32);
    std::uniform_int_distribution<uint16_t> distribution(0, std::numeric_limits<uint8_t>::max());
    if (offset > 0) {
        for (int j = 0; j < offset; ++j) {
            entropy[j] = static_cast<uint8_t>(distribution(engine));
        }
    }
    for (size_t i = 0; i < 32; ++i) {
        entropy[i] = static_cast<uint8_t>(distribution(engine));
    }
    memcpy(data, entropy.data(), 32);
}

