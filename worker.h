#ifndef WORKER_H
#define WORKER_H

#include <base58.h>
#include <bip32.h>
#include <bip39.h>
#include <bip39_english.h>
#include <db.h>
#include <derive.h>
#include <entropy.h>
#include <illbloom.h>
#include <simplelogger.h>
#include <timer.h>

#include <time.h>
#include <errno.h>

#include <fstream>

void calculate_from_seed(std::string& seed, std::string& mnemonic, bool output_debug);
void monitor();
void worker(int thr_id, size_t bitlen, uint32_t& increment, int offset);
void hexStringToBytes(const std::string& hex, char *buf);

#endif // WORKER_H
