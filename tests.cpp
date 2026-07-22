#include <tests.h>

void single_thread_debug(size_t bitlen, uint32_t& increment, int offset)
{
    char buf[32], hexbuf[128];
    std::string mnemonic, seed;

    memset(hexbuf, 0, sizeof(hexbuf));

    //local
    uint32_t our_increment = increment;

    while (true) {

         std::string illbloom = emulate_cryptojs_wordarray(our_increment);
         hexStringToBytes(illbloom, buf);
         entropy_to_mnemonic(&buf[0], bitlen, mnemonic);
         mnemonic_to_seed(mnemonic, seed);
         calculate_from_seed(seed, mnemonic, our_increment, false);

         for (int i=0; i<bitlen/8; i++) {
             sprintf(hexbuf+(i*2), "%02hhx", buf[i]);
         }

         printf("%08x - %s %s\n", our_increment, hexbuf, mnemonic.c_str());

         our_increment += 1;
    }
}
