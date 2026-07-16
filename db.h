#ifndef DB_H
#define DB_H

#include <stdio.h>
#include <string.h>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <mutex>
#include <thread>
#include <algorithm>
#include <vector>

#include <timer.h>

void initdb();
bool searchaddress(std::string address);

#endif // DB_H
