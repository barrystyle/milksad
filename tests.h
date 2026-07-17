#ifndef TESTS_H
#define TESTS_H

#include <base58.h>
#include <bip32.h>
#include <bip39.h>
#include <bip39_english.h>
#include <db.h>
#include <derive.h>
#include <entropy.h>
#include <simplelogger.h>
#include <timer.h>
#include <worker.h>

#include <time.h>
#include <errno.h>

#include <fstream>

void single_thread_debug(size_t bitlen, uint32_t& increment, int offset);

#endif // TESTS_H
