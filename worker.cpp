#include <worker.h>

extern bool output_debug;
extern uint32_t maxthreads;
extern std::vector<uint32_t> perfcount;

void calculate_from_seed(std::string& seed, std::string& mnemonic, bool output_debug)
{
    pairSet result;
    std::string path;

    std::vector<uint8_t> seed_vec = hex_to_vec(seed);

    path = "m/44'/0'/0'/0/0";
    derive_keys_p2pkh(seed_vec, path, result);
    if (output_debug) {
        printf("%s p2pkh  | c: %48s u: %48s\n", path.c_str(), result.wif_compressed_pubkey.c_str(), result.wif_uncompressed_pubkey.c_str());
    }

    //search db
    if (searchaddress(result.wif_compressed_pubkey) || searchaddress(result.wif_uncompressed_pubkey)) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "mnemonic: %s\nseed: %48s | c: %48s u: %48s\n", mnemonic.c_str(), seed.c_str(), result.wif_compressed_pubkey.c_str(), result.wif_uncompressed_pubkey.c_str());
        filelogger(std::string(buffer));
    }

    path = "m/49'/0'/0'/0/0";
    derive_keys_p2sh_p2wpkh(seed_vec, path, result);
    if (output_debug) {
        printf("%s p2sh   | c: %48s\n", path.c_str(), result.wif_compressed_pubkey.c_str());
    }

    //search db
    if (searchaddress(result.wif_compressed_pubkey)) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "mnemonic: %s\nseed: %48s | c: %48s\n", mnemonic.c_str(), seed.c_str(), result.wif_compressed_pubkey.c_str());
        filelogger(std::string(buffer));
    }

    path = "m/84'/0'/0'/0/0";
    derive_keys_p2wpkh(seed_vec, path, result);
    if (output_debug) {
        printf("%s p2wpkh | c: %48s\n", path.c_str(), result.wif_compressed_pubkey.c_str());
    }

    //search db
    if (searchaddress(result.wif_compressed_pubkey)) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "mnemonic: %s\nseed: %48s | c: %48s\n", mnemonic.c_str(), seed.c_str(), result.wif_compressed_pubkey.c_str());
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

void worker(int thr_id, size_t bitlen, uint32_t& increment)
{
    char buf[32];
    std::string mnemonic, seed;

    printf("launching thr%d (bitlen: %d, increment: %d)\n", thr_id, bitlen, increment);

    //local
    perfcount[thr_id] = 0;
    uint32_t our_increment = increment + thr_id;

    while (true) {

         //calculate seed from merseinne
         get_entropy(our_increment, &buf[0]);
         entropy_to_mnemonic(&buf[0], bitlen, mnemonic);
         mnemonic_to_seed(mnemonic, seed);

         //print mnemonic
         if (output_debug) {
             printf("\n%s\n%s\n", seed.c_str(), mnemonic.c_str());
         }

         //calculate keys from seed
         calculate_from_seed(seed, mnemonic, output_debug);

         perfcount[thr_id] += 1;
         our_increment += maxthreads;

    }
}
