/*
 * File: cp_audit_linux.cpp
 * Author: Landon Snellgrove
 * Date: 2025-11-05
 * Description: 
 *   This program audits some system information that might be useful for cyberpatriot comps
 *   this program does NOT do any work for you can only audit information and you decipher what it means
 * 
 * Compilation:
 *   g++ -std=c++17 -O2 -o audit path_to_scripts/cp_audit_linux.cpp
 * 
 * Usage:
 *   ./audit
 * 
 * Notes:
 *   - Make sure to compile with C++17 standard.
 *   - Optimization level -O2 is recommended for best performance.
 *   - Not sure if this file actually works it is untested
 */

#include <iostream>
#include <cstdio>
#include <string>

std::string run_cmd(const std::string &cmd) {
    std::string output;
    char buffer[256];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "ERROR: popen failed\n";

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    return output.empty() ? "(no output)\n" : output;
}

void header(const std::string &title) {
    std::cout << "\n====================== " << title << " ======================\n";
}

int main() {
    header("Current User");
    std::cout << run_cmd("whoami") << run_cmd("id") << "\n";

    header("OS Info");
    std::cout << run_cmd("cat /etc/os-release || uname -a") << "\n";

    header("Users with Administrative Privileges (UID 0)");
    std::cout << run_cmd("awk -F: '($3==0){print $1}' /etc/passwd") << "\n";

    header("Users in sudo or wheel group");
    std::cout << run_cmd("getent group sudo wheel") << "\n";

    header("Users with Empty Passwords or No Password Set");
    std::cout << run_cmd("awk -F: '($2==\"\" || $2==\"!\") {print $1}' /etc/shadow 2>/dev/null") << "\n";

    header("World-Writable Files (timeout 3s)");
    std::cout << run_cmd("timeout 3s find / -xdev -type f -perm -0002 2>/dev/null | head -n 50") << "\n";

    header("SUID Files (timeout 3s)");
    std::cout << run_cmd("timeout 3s find / -type f -perm -4000 2>/dev/null | head -n 50") << "\n";;

    header("Listening Ports");
    std::cout << run_cmd("ss -tuln") << "\n";

    header("Running Services");
    std::cout << run_cmd("systemctl list-units --type=service --state=running --no-legend") << "\n";

    header("SSH Config");
    std::cout << run_cmd("grep -Ei 'PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null") << "\n";

    header("Firewall Status (ufw)");
    std::cout << run_cmd("which ufw >/dev/null && ufw status verbose || echo 'ufw not installed'") << "\n";

    header("Cron Jobs");
    std::cout << run_cmd("echo 'System cron directories:'; ls -la /etc/cron.* 2>/dev/null; echo; echo 'System crontab:'; head -n 50 /etc/crontab 2>/dev/null") << "\n";

    std::cout << "\nAudit Complete\n";
    return 0;
}