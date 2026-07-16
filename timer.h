#ifndef TIMER_H
#define TIMER_H

// basic timer class
// barrystyle 17092023

#include <iostream>
#include <chrono>
#include <vector>

class Timer
{
    private:
        const int winsz = 128;
        std::vector<uint64_t> window;
        std::chrono::_V2::system_clock::time_point t1;
        std::chrono::_V2::system_clock::time_point t2;
        uint64_t average() {
            while (window.size() > winsz) {
                window.pop_back();
            }
            uint64_t average = 0;
            for (int i=0; i<window.size(); i++) {
                average += window[i];
            }
            return average / window.size();
        }
    public:
        Timer() {
            window.clear();
        }
        void start() {
            t1 = std::chrono::high_resolution_clock::now();
        }
        void stop() {
            t2 = std::chrono::high_resolution_clock::now();
        }
        uint64_t between_milliseconds() {
            window.push_back((uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count());
            return average();
        }
        uint64_t between_microseconds() {
            window.push_back((uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count());
            return average();
        }
        uint64_t between_nanoseconds() {
            window.push_back((uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count());
            return average();
        }
};

#endif // TIMER_H