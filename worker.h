#ifndef WORKER_H
#define WORKER_H

#include <base58.h>
#include <bip32.h>
#include <bip39.h>
#include <bip39_english.h>
#include <db.h>
#include <derive.h>
#include <entropy.h>
#include <simplelogger.h>
#include <timer.h>

#include <time.h>
#include <errno.h>

#include <fstream>

void monitor();
void worker(int thr_id, size_t bitlen, uint32_t& increment, int offset);

#endif // WORKER_H
