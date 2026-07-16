#include "db.h"

std::vector<std::string> addresses;

void initdb()
{
    std::ifstream file("vuln_bitcoin.txt");

    Timer timer;

    //read into vec
    timer.start();
    std::string line;
    while (std::getline(file, line)) {
        addresses.push_back(line);
    }
    int linec = addresses.size();
    timer.stop();
    printf("read %d entries into vector in %ldms\n", linec, timer.between_milliseconds());
}

bool searchaddress(std::string address)
{
    if (std::find(addresses.begin(), addresses.end(), address) != addresses.end()) {
        return true;
    }
    return false;
}
