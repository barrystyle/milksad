// Copyright (c) 2023 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <fstream>
#include <mutex>

static std::mutex g_logger_mutex;
static std::string logfile("output.log");

static void filelogger_inner(std::string& data)
{
    std::fstream logStream;
    logStream.open(logfile, std::ios::app);
    if (!logStream.is_open()) {
        return;
    }
    logStream << data << "\n";
    logStream.close();
}

void filelogger(std::string data)
{
    std::lock_guard<std::mutex> guard(g_logger_mutex);
    filelogger_inner(data);
}
