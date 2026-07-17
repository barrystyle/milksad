#include "db.h"
#include <unordered_set>
#include <fstream>

std::unordered_set<std::string> addresses;

void initdb()
{
    std::ifstream file("vuln_bitcoin.txt");

    Timer timer;

    //read into vec
    timer.start();
    std::string line;
    addresses.reserve(52000000);
    while (std::getline(file, line)) {
        addresses.insert(std::move(line));
    }
    int linec = addresses.size();
    timer.stop();
    printf("read %d entries into vector in %ldms\n", linec, timer.between_milliseconds());
}

bool searchaddress(std::string address)
{
    return addresses.count(address) != 0;
}
