#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

struct PatchSig {
    std::string sig_str;
    int offset = 0;
    std::string ref;
    PatchSig(const std::string& s, int o = 0, const std::string& r = "") : sig_str(s), offset(o), ref(r) {}
};

struct PatchDef {
    std::vector<PatchSig> signatures;
    std::vector<uint8_t> patch_bytes;
    std::string name;
};

struct DetectedPatch {
    unsigned long offset;
    std::vector<uint8_t> original_bytes;
    std::vector<uint8_t> patch_bytes;
    std::string name;
};

unsigned long resolve_ref(const std::vector<uint8_t>& data, int match_offset, const PatchSig& sig) {
    if (sig.ref == "call" || sig.ref == "jmp") {
        int instr_offset = match_offset + sig.offset;
        if (static_cast<size_t>(instr_offset) + 5 > data.size()) return instr_offset;
        int32_t rel = *reinterpret_cast<const int32_t*>(&data[instr_offset + 1]);
        return static_cast<unsigned long>(instr_offset + 5 + rel);
    } else if (sig.ref == "lea") {
        int instr_offset = match_offset + sig.offset;
        if (static_cast<size_t>(instr_offset) + 7 > data.size()) return instr_offset;
        int32_t rel = *reinterpret_cast<const int32_t*>(&data[instr_offset + 3]);
        return static_cast<unsigned long>(instr_offset + 7 + rel);
    }
    return static_cast<unsigned long>(match_offset + sig.offset);
}

std::vector<int> parse_signature(const std::string& sig) {
    std::vector<int> pattern;
    std::istringstream iss(sig);
    std::string byte;
    while (iss >> byte) {
        if (byte == "?")
            pattern.push_back(-1);
        else
            pattern.push_back(std::stoi(byte, nullptr, 16));
    }
    return pattern;
}

std::vector<int> find_all_signatures(const std::vector<uint8_t>& data, const std::vector<int>& pattern) {
    std::vector<int> matches;
    for (size_t i = 0; i + pattern.size() <= data.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] != -1 && data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) matches.push_back(static_cast<int>(i));
    }
    return matches;
}

std::vector<DetectedPatch> detect_patches(const std::string& filename) {
    std::vector<PatchDef> patch_defs = {
        // NOP patches
        { { PatchSig("41 B8 88 13 00 00 E8 ? ? ? ?", 0x6) }, {0x90, 0x90, 0x90, 0x90, 0x90}, "invalidate1" },
        { { PatchSig("41 B8 98 3A 00 00 E8 ? ? ? ?", 0x6) }, {0x90, 0x90, 0x90, 0x90, 0x90}, "invalidate2" },

        // ret0 patch: license_notification
        { { PatchSig("48 8d ? ? ? ? ? e8 ? ? ? ? 48 89 c1 ff ? ? ? ? ? ? 8b", 0, "lea") }, {0x48, 0x31, 0xC0, 0xC3}, "license_notification" },

        // ret0 patch: license_check
        { {
            PatchSig("45 31 ? e8 ? ? ? ? 85 c0 75 ? ? 8d", 0x3, "call"),
            PatchSig("0f 11 ? ? ? 31 ? 45 31 ? 45 31 ? e8 ? ? ? ?", 0xD, "call"),
            PatchSig("e8 ? ? ? ? ? 8b ? ? ? ? ? 85 c0 0f 94 ? ? 74", 0, "call")
        }, {0x48, 0x31, 0xC0, 0xC3}, "license_check" },

        // ret1 patch: server_validate
        { {
            PatchSig("8b 51 ? 48 83 c1 08 e9 ? ? ? ?", 0x7, "jmp"),
            PatchSig("56 57 53 48 83 ec ? 89 d6 48 89 cf b9 ? 00 00 00 e8 ? ? ? ?")
        }, {0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0, 0xC3}, "server_validate" },
    };


    std::ifstream file(filename, std::ios::binary);
    if (!file) return {};
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), {});

    std::vector<DetectedPatch> detected;
    for (const auto& patch : patch_defs) {
        for (const auto& sig : patch.signatures) {
            auto pattern = parse_signature(sig.sig_str);
            auto matches = find_all_signatures(data, pattern);
            if (matches.size() == 1) {
                int match_offset = matches[0];
                unsigned long patch_offset = resolve_ref(data, match_offset, sig);
                if (patch_offset + patch.patch_bytes.size() > data.size()) continue;
                std::vector<uint8_t> orig(data.begin() + patch_offset, data.begin() + patch_offset + patch.patch_bytes.size());
                if (orig != patch.patch_bytes) {
                    detected.push_back({ patch_offset, orig, patch.patch_bytes, patch.name });
                    break;
                }
            }
        }
    }
    return detected;
}

std::string detect_version(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";

    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    std::regex version_regex1("version=(\\d{4})");
    std::regex version_regex2("sublime_text_(\\d{4})");
    std::smatch match;

    if (std::regex_search(data, match, version_regex1)) {
        return match[1];
    }
    if (std::regex_search(data, match, version_regex2)) {
        return match[1];
    }
    return "";
}

std::string toLowercase(const std::string& str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return lowerStr;
}

std::map<std::string, std::string> versionMap = {
    {toLowercase("924C781AC4FCD21A2B46C73B07D7BC27"), "4126"},
    {toLowercase("654F4259E066F90F4964E695CF808AD0"), "4143"},
    {toLowercase("15BB398D5663B89A44372EF15F70A46F"), "4152"},
    {toLowercase("5B3C8CEA0FCA4323F0E8A994209042A8"), "4169"},
    {toLowercase("3874916e032eeffede48b6dad4dd7f3c"), "4192"},
    {toLowercase("671b865fbde25cdcbd0144d3e7baea31"), "4200"}
};

bool IsElevated() {
    bool isElevated = false;
    HANDLE hToken = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION
        elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
    }

    if (hToken) {
        CloseHandle(hToken);
    }

    return isElevated;
}

void msgEnd() {
    std::cout << "\nPaying $99 for a license is stupid!\n" << std::endl;
    system("timeout /t 5");
    system("cls");
    std::cout << "Thank you for using. Made by @b1uedev" << std::endl;
    system("pause");
    exit(0);
}

bool checkDir(const std::string& s_path) {
    std::fstream file(s_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    return true;
}


int get_patch_option(std::string& s_path) {
    bool auto_path = true;

    s_path = "C:\\Program Files\\Sublime Text\\sublime_text.exe";
    if (!checkDir(s_path)) {
        std::cout << "Enter the path: ";
        std::getline(std::cin, s_path);
        s_path.erase(std::remove(s_path.begin(), s_path.end(), '\"'), s_path.end());
        auto_path = false;
    }

    int option = 0;
    std::cout << "SublimePatch by @b1uedev.\n" << std::endl;
    // Try to check MD5 hash first
    bool hash_found = false;
    std::string detected_version;
    std::string command, processedHashString;
    for (const auto& entry : versionMap) {
        std::string hash = entry.first;
        std::string version = entry.second;
        command = "cmd /c certutil -hashfile \"" + s_path  + "\" md5 | find /i \"" + hash + "\" || exit";
        int wlen = MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, nullptr, 0);
        std::wstring wcommand(wlen, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, command.c_str(), -1, &wcommand[0], wlen);
        LPWSTR lpCommandLine = &wcommand[0];

        SECURITY_ATTRIBUTES saAttr = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
        HANDLE hChildStdoutRd, hChildStdoutWr;

        if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0)) {
            std::cerr << "Error creating pipe." << std::endl;
            return 0;
        }

        STARTUPINFOW si = {};
        si.cb = sizeof(STARTUPINFOW);
        PROCESS_INFORMATION pi;

        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hChildStdoutWr;
        si.hStdError = hChildStdoutWr;

        if (CreateProcessW(nullptr, lpCommandLine, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hChildStdoutWr);

            char buf[1024];
            DWORD bytesRead;
            std::string result;
            while (ReadFile(hChildStdoutRd, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
                result.append(buf, bytesRead);
            }

            CloseHandle(hChildStdoutRd);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            processedHashString = toLowercase(result);
            processedHashString.erase(std::remove_if(processedHashString.begin(), processedHashString.end(), ::isspace), processedHashString.end());

            if (hash == processedHashString) {
                hash_found = true;
                detected_version = version;
                break;
            }
        }
    }

    if (hash_found) {
        std::cout << "You have version " << detected_version << " installed." << std::endl;
        std::cout << "Press 1 to patch and activate." << std::endl;
        if (auto_path) std::cout << "Press 2 to manually patch a custom path." << std::endl;
        std::cout << "Press 0 to quit." << std::endl;
    } else {
        std::cout << "[WARNING] Could not verify original file by MD5 hash.\n";
        std::string version = detect_version(s_path);
        if (!version.empty()) {
            std::cout << "Detected version: " << version << std::endl;
        } else {
            std::cout << "Could not detect version." << std::endl;
        }
        std::cout << "Proceed with caution. Press 1 to patch and activate anyway, or 0 to quit." << std::endl;
    }

    std::cin >> option;
    return option;
}


int main() {
    /// Needs to run as administrator.
    if (!IsElevated()) {
        std::cout << "You have to run this program as Administrator." << std::endl;
        system("PAUSE");
        return 1;
    }

    std::string s_path;
    int option = get_patch_option(s_path);
    switch (option) {
    case 1: {
        std::fstream file(s_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!file.is_open()) {
            std::cout << "\nError: Could not open file for writing. Have you closed ST entirely?\n" << std::endl;
            system("pause");
            break;
        } else {
        auto detected = detect_patches(s_path);
            if (detected.empty()) {
                std::cout << "\nNo patches detected. Is your ST newly installed?\n" << std::endl;
                system("pause");
                break;
            }
            for (const auto& dp : detected) {
                file.seekg(dp.offset, std::ios::beg);
                std::vector<unsigned char> read_bytes(dp.original_bytes.size());
                file.read(reinterpret_cast<char*>(read_bytes.data()), dp.original_bytes.size());

                if (read_bytes == dp.original_bytes) {
                    std::cout << "Offset: 0x" << std::hex << dp.offset <<  " - " << dp.name << std::endl;
                    std::cout << "Original Data:";
                    for (unsigned char byte : read_bytes) {
                        std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                    }
                    std::cout << std::endl;

                    file.seekp(dp.offset, std::ios::beg);
                    file.write(reinterpret_cast<const char*>(dp.patch_bytes.data()), dp.patch_bytes.size());
                    file.flush();

                    std::cout << "Patched Data:";
                    for (unsigned char byte : dp.patch_bytes) {
                        std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                    }
                    std::cout << std::endl;
                }
            }
            file.close();
        }
        msgEnd();
        break;
    }
    case 2: {
        std::string custom_path;
        std::cout << "Enter the full path to your ST executable: ";
        std::cin.ignore();
        std::getline(std::cin, custom_path);
        custom_path.erase(std::remove(custom_path.begin(), custom_path.end(), '\"'), custom_path.end());

        if (!checkDir(custom_path)) {
            std::cout << "\nError: Could not open file. Please check the path and try again. Make sure ST is not running.\n" << std::endl;
            system("pause");
            break;
        }

        std::fstream file(custom_path, std::ios::in | std::ios::out | std::ios::binary);
        if (!file.is_open()) {
            std::cout << "\nError: Could not open file for writing. Have you closed ST entirely?\n" << std::endl;
            system("pause");
            break;
        } else {
            auto detected = detect_patches(custom_path);
            if (detected.empty()) {
                std::cout << "\nNo patches detected. Is your ST newly installed?\n" << std::endl;
                system("pause");
                break;
            }
            for (const auto& dp : detected) {
                file.seekg(dp.offset, std::ios::beg);
                std::vector<unsigned char> read_bytes(dp.original_bytes.size());
                file.read(reinterpret_cast<char*>(read_bytes.data()), dp.original_bytes.size());

                if (read_bytes == dp.original_bytes) {
                    std::cout << "Offset: 0x" << std::hex << dp.offset <<  " - " << dp.name << std::endl;
                    std::cout << "Original Data:";
                    for (unsigned char byte : read_bytes) {
                        std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                    }
                    std::cout << std::endl;

                    file.seekp(dp.offset, std::ios::beg);
                    file.write(reinterpret_cast<const char*>(dp.patch_bytes.data()), dp.patch_bytes.size());
                    file.flush();

                    std::cout << "Patched Data:";
                    for (unsigned char byte : dp.patch_bytes) {
                        std::cout << " " << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                    }
                    std::cout << std::endl;
                }
            }
            file.close();
        }
        msgEnd();
        break;
    }
    case 0:
        system("PAUSE");
        exit(0);
    default:
        std::cout << "Invalid input." << std::endl;
        system("PAUSE");
        exit(1);
    }

    return 0;
}
