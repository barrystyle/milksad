#include "base58.h"
#include <bip32.h>
#include <bip39.h>
#include <bip39_english.h>
#include <db.h>
#include <derive.h>
#include <entropy.h>
#include <timer.h>
#include <tests.h>
#include <worker.h>
#include <fstream>

int offset = 0;
size_t bitlen = 128;
uint32_t increment = 0;
uint32_t maxthreads = 6;
std::vector<uint32_t> perfcount;

bool output_debug = false;
bool testing_debug = false;

int main()
{
    if (testing_debug) {
        single_thread_debug(bitlen, increment, offset);
        return 0;
    }

    perfcount.resize(maxthreads);

    //load addresses
    initdb();

    //launch monitor
    std::vector<std::thread> workers;
    workers.push_back(std::thread(monitor));

    //launch threads
    for (int i=0; i<(int)maxthreads; i++) {
         workers.push_back(std::thread(worker, i, bitlen, std::ref(increment), offset));
    }

    for (int i=0; i<(int)maxthreads+1; i++) {
         if (workers[i].joinable()) workers[i].join();
    }

    return 0;
}
