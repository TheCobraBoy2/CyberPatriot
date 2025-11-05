/*
 * File: cp_audit_windows.cpp
 * Author: Landon Snellgrove
 * Date: 2025-11-05
 * Description:
 *   This program audits some system information that might be useful for cyberpatriot comps
 *   this program does NOT do any work for you can only audit information and you decipher what it means
 * 
 * Compilation (Windows):
 *   g++ -std=c++17 -O2 -o audit cp_audit_windows.cpp
 * 
 * Usage:
 *   ./audit.exe
 * 
 * Notes:
 *   - Make sure to compile with C++17 standard.
 *   - Optimization level -O2 is recommended for good performance.
 *   - Executable will be named audit.exe on Windows.
 *   - This program does appear to work as intended only tested on my personal computer tho
 */
#include <iostream>
#include <string>
#include <cstdio>

std::string run_cmd(const std::string& cmd) {
    std::string result;
    const int buffer_size = 128;
    char buffer[buffer_size];

    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "ERROR: _popen failed\n";

    while (fgets(buffer, buffer_size, pipe)) {
        result += buffer;
    }
    _pclose(pipe);
    return result.empty() ? "(no output)\n" : result;
}

void header(const std::string& title) {
    std::cout << "\n============================================================\n";
    std::cout << title << "\n------------------------------------------------------------\n";
}

int main() {
    header("Windows CP Audit (Snellgrove Landon)");

    header("System Information (Can essentially disregard)");
    std::cout << run_cmd("systeminfo");

    header("Local Users");
    std::cout << run_cmd("net user");

    header("Running Services");
    std::cout << run_cmd("powershell -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'}\"");

    header("Firewall Status");
    std::cout << run_cmd("netsh advfirewall show allprofiles");

    header("Listening Network Ports");
    std::cout << run_cmd("netstat -ano");

    header("Administrators Group");
    std::cout << run_cmd("net localgroup Administrators");

    std::cout << "\nAudit complete. Run with Administrator privileges for best results.\n";

    return 0;
}