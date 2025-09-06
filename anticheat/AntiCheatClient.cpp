#include "InjectorGuard.h"
#include "MemoryGuard.h"
#include "ApiGuard.h"
#include "PatternAnalyzer.h"
#include "CommManager.h"
#include <thread>
#include <vector>
#include <string>

int main() {
    std::vector<std::wstring> whitelist = {L"metin2client.exe", L"kernel32.dll", L"user32.dll", L"gdi32.dll"};
    CommManager comm("127.0.0.1", 60000); // Sunucu IP ve port

    comm.Connect();

    std::thread t1(MonitorInjectedModules, whitelist, &comm);
    std::thread t2(MonitorMemoryIntegrity, &comm);
    std::thread t3(MonitorPatterns, &comm);
    std::thread t4(MonitorApiHooks, &comm);

    t1.join();
    t2.join();
    t3.join();
    t4.join();
    return 0;
}