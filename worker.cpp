#include <worker.h>

extern bool output_debug;
extern uint32_t maxthreads;
extern std::vector<uint32_t> perfcount;

void calculate_from_seed(std::string& seed, std::string& mnemonic, uint32_t& our_increment, bool output_debug)
{
    pairSet result;
    
    const std::string path0 = "m/44'/0'/0'/0/0";
    std::vector<uint8_t> seed_vec = hex_to_vec(seed);
    derive_keys_p2pkh(seed_vec, path0, result);
    if (output_debug) {
        printf("%s p2pkh  | c: %48s\n", path0.c_str(), result.wif_compressed_pubkey.c_str());
    }

    //search db
    if (searchaddress(result.wif_compressed_pubkey)) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "increment: %08x\nmnemonic: %s\nseed: %48s | c: %48s\n", our_increment, mnemonic.c_str(), seed.c_str(), result.wif_compressed_pubkey.c_str());
        filelogger(std::string(buffer));
    }

    const std::string path1 = "m/49'/0'/0'/0/0";
    derive_keys_p2sh_p2wpkh(seed_vec, path1, result);
    if (output_debug) {
        printf("%s p2sh   | c: %48s\n", path1.c_str(), result.wif_compressed_pubkey.c_str());
    }

    //search db
    if (searchaddress(result.wif_compressed_pubkey)) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "increment: %08x\nmnemonic: %s\nseed: %48s | c: %48s\n", our_increment, mnemonic.c_str(), seed.c_str(), result.wif_compressed_pubkey.c_str());
        filelogger(std::string(buffer));
    }

    const std::string path2 = "m/84'/0'/0'/0/0";
    derive_keys_p2wpkh(seed_vec, path2, result);
    if (output_debug) {
        printf("%s p2wpkh | c: %48s\n", path2.c_str(), result.wif_compressed_pubkey.c_str());
    }

    //search db
    if (searchaddress(result.wif_compressed_pubkey)) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "increment: %08x\nmnemonic: %s\nseed: %48s | c: %48s\n", our_increment, mnemonic.c_str(), seed.c_str(), result.wif_compressed_pubkey.c_str());
        filelogger(std::string(buffer));
    }
}

int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

void monitor()
{
    Timer timer;
    timer.start();

    const uint32_t monitor_increment = 5000;

    while (true) {

         uint32_t perftotal = 0;
         for (int i=0; i<maxthreads; i++) {
             perftotal += perfcount[i];
         }

         if (perftotal > monitor_increment) {
             timer.stop();
             uint64_t work_time = timer.between_milliseconds();
             double per_minute = (60000 / (double) work_time) * monitor_increment;
             //printf("%d iterations in %llums\n", monitor_increment, work_time);
             printf("%.0f iterations per minute\n", per_minute);
             for (int i=0; i<maxthreads; i++) {
                 perfcount[i] = 0;
             }
             timer.start();
         }

         msleep(25);
    }
}

void hexStringToBytes(const std::string& hex, char *buf) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = std::isxdigit((unsigned char)hex[i])   ? std::stoi(hex.substr(i, 1), nullptr, 16) : -1;
        int lo = std::isxdigit((unsigned char)hex[i+1]) ? std::stoi(hex.substr(i+1, 1), nullptr, 16) : -1;
        if (hi < 0 || lo < 0)
            throw std::invalid_argument("invalid hex character");
        bytes.push_back((unsigned char)((hi << 4) | lo));
    }
    memcpy(buf, bytes.data(), bytes.size());
}

void worker(int thr_id, size_t bitlen, uint32_t& increment, int offset)
{
    char buf[32];
    std::string mnemonic, seed;

    printf("launching thr%d (bitlen: %d, increment: %08x)\n", thr_id, bitlen, increment);

    //local
    perfcount[thr_id] = 0;
    uint32_t our_increment = increment + thr_id;

    while (true) {

         std::string illbloom = emulate_cryptojs_wordarray(our_increment);
         hexStringToBytes(illbloom, buf);
         entropy_to_mnemonic(&buf[0], bitlen, mnemonic);
         mnemonic_to_seed(mnemonic, seed);

         //print mnemonic
         if (output_debug) {
             printf("\n%s\n%s\n", seed.c_str(), mnemonic.c_str());
         }

         //calculate keys from seed
         calculate_from_seed(seed, mnemonic, our_increment, output_debug);

         perfcount[thr_id] += 1;
         our_increment += maxthreads;

         if (our_increment % 10000 == 0) {
             printf("*thread%d at timestamp %08x\n", thr_id, our_increment);
         }
    }
}
