#include "db.h"
#include <unordered_set>
#include <fstream>

std::unordered_set<std::string> addresses;

void initdb()
{
    std::ifstream file0("vuln_bitcoin.txt");
    std::ifstream file1("vuln_bitcoin.txt");

    Timer timer;

    //count lines
    int estlines = 0;
    std::string temp;
    while (std::getline(file0, temp)) {
        ++estlines;
    }

    //read into vec
    timer.start();
    std::string line;
    addresses.reserve(estlines);
    while (std::getline(file1, line)) {
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
