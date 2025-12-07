#pragma once
#include <string>
#include <thread>
#include <ctime>
#include <vector>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

// Key info structure
struct KeyInfo {
    std::string duration;
    std::string amount;
    std::string expiresAt;
    std::string timeRemaining;
    int timeRemainingSeconds;
    std::string hwid;
    std::string ip;
    std::string usedAt;
    std::string createdAt;
    bool isValid;
    
    KeyInfo() : timeRemainingSeconds(0), isValid(false) {}
};

// Message structure
struct Message {
    std::string id;
    std::string title;
    std::string content;
    std::string type; // info, warning, error, success
    std::string createdAt;
    bool isValid;
    
    Message() : isValid(false) {}
};

// KeyAuth-like encryption namespace to confuse reverse engineers
namespace KeyAuth {
    class encryption {
    private:
        static std::string xorEncrypt(const std::string& data, const std::string& key) {
            std::string result = data;
            for (size_t i = 0; i < result.length(); i++) {
                result[i] ^= key[i % key.length()];
            }
            return result;
        }
        
        static std::string base64Encode(const std::string& data) {
            const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string encoded;
            int val = 0, valb = -6;
            for (unsigned char c : data) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
            while (encoded.size() % 4) encoded.push_back('=');
            return encoded;
        }
        
        static std::string base64Decode(const std::string& data) {
            const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string decoded;
            int val = 0, valb = -8;
            for (char c : data) {
                if (c == '=') break;
                const char* pos = strchr(base64_chars, c);
                if (!pos) continue;
                val = (val << 6) + (pos - base64_chars);
                valb += 6;
                if (valb >= 0) {
                    decoded.push_back(char((val >> valb) & 0xFF));
                    valb -= 8;
                }
            }
            return decoded;
        }
        
    public:
        static std::string encrypt(const std::string& data, const std::string& key) {
            std::string xored = xorEncrypt(data, key);
            return base64Encode(xored);
        }
        
        static std::string decrypt(const std::string& data, const std::string& key) {
            std::string decoded = base64Decode(data);
            return xorEncrypt(decoded, key);
        }
        
        static std::string hash(const std::string& data) {
            unsigned long hash = 5381;
            for (size_t i = 0; i < data.length(); i++) {
                hash = ((hash << 5) + hash) + data[i];
            }
            return std::to_string(hash);
        }
    };
    
    // KeyAuth-like helper functions
    namespace helper {
        static std::string initKeyAuth(const std::string& name, const std::string& ownerid, const std::string& secret) {
            return encryption::encrypt(name + ownerid, secret);
        }
    }
}

// Security namespace for protection features
namespace AuthSecurity {
    // Request signing to prevent tampering
    class RequestSigner {
    public:
        static std::string signRequest(const std::string& data, const std::string& key) {
            std::string combined = data + key;
            unsigned long hash = 5381;
            for (size_t i = 0; i < combined.length(); i++) {
                hash = ((hash << 5) + hash) + combined[i];
            }
            return std::to_string(hash);
        }
        
        static bool verifySignature(const std::string& data, const std::string& signature, const std::string& key) {
            std::string expected = signRequest(data, key);
            return expected == signature;
        }
    };
    
    // Time validation to prevent replay attacks
    class TimeValidator {
    private:
        static inline time_t lastRequestTime = 0;
        static inline int requestCount = 0;
        
    public:
        static bool isValidRequest() {
            time_t currentTime = time(nullptr);
            if (lastRequestTime != 0 && currentTime < lastRequestTime) {
                return false;
            }
            lastRequestTime = currentTime;
            requestCount++;
            return true;
        }
        
        static void reset() {
            lastRequestTime = 0;
            requestCount = 0;
        }
    };
    
    // Memory protection - clear sensitive data
    class MemoryProtection {
    public:
        static void secureClear(std::string& data) {
            if (data.empty()) return;
            for (size_t i = 0; i < data.length(); i++) data[i] = 0xFF;
            for (size_t i = 0; i < data.length(); i++) data[i] = 0x00;
            for (size_t i = 0; i < data.length(); i++) data[i] = 0xAA;
            data.clear();
        }
        
        static void secureClear(char* data, size_t length) {
            if (!data || length == 0) return;
            for (size_t i = 0; i < length; i++) data[i] = 0xFF;
            for (size_t i = 0; i < length; i++) data[i] = 0x00;
            for (size_t i = 0; i < length; i++) data[i] = 0xAA;
        }
    };
    
    // Code integrity check
    class IntegrityCheck {
    public:
        static DWORD calculateChecksum(const void* data, size_t size) {
            DWORD checksum = 0;
            const BYTE* bytes = (const BYTE*)data;
            for (size_t i = 0; i < size; i++) {
                checksum = ((checksum << 1) | (checksum >> 31)) ^ bytes[i];
            }
            return checksum;
        }
        
        static bool verifyFunctionIntegrity(void* funcPtr, DWORD expectedChecksum, size_t funcSize) {
            if (!funcPtr) return false;
            DWORD actualChecksum = calculateChecksum(funcPtr, funcSize);
            return actualChecksum == expectedChecksum;
        }
    };
    
    // Anti-hook detection
    class AntiHook {
    public:
        static bool isFunctionHooked(void* funcPtr) {
            if (!funcPtr) return true;
            BYTE* bytes = (BYTE*)funcPtr;
            if (bytes[0] == 0xE9 || bytes[0] == 0xEB || bytes[0] == 0xE8 || bytes[0] == 0xCC) {
                return true;
            }
            return false;
        }
        
        static bool checkCriticalFunctions() {
            HMODULE winhttp = LoadLibraryA("winhttp.dll");
            if (winhttp) {
                void* sendFunc = GetProcAddress(winhttp, "WinHttpSendRequest");
                if (sendFunc && isFunctionHooked(sendFunc)) {
                    FreeLibrary(winhttp);
                    return true;
                }
                FreeLibrary(winhttp);
            }
            return false;
        }
    };
    
    // Request obfuscation
    class RequestObfuscator {
    public:
        static std::string obfuscateEndpoint(const std::string& endpoint) {
            std::string result = endpoint;
            std::reverse(result.begin(), result.end());
            for (size_t i = 0; i < result.length(); i++) {
                result[i] ^= 0x5A;
            }
            return result;
        }
        
        static std::string deobfuscateEndpoint(const std::string& obfuscated) {
            std::string result = obfuscated;
            for (size_t i = 0; i < result.length(); i++) {
                result[i] ^= 0x5A;
            }
            std::reverse(result.begin(), result.end());
            return result;
        }
    };
}

// KeyAuth-like class name to confuse reverse engineers
class AuthClient {
private:
    std::string serverUrl;
    std::string hwid;
    std::string localIp;
    std::string lastError;
    std::string accountId;
    std::string apiToken;
    std::string validatedKey;
    bool isAuthenticated;
    KeyInfo keyInfo;
    std::vector<Message> messages;
    
    std::string makeRequest(const std::string& endpoint, const std::string& jsonBody);
    std::string generateHWID();
    std::string getLocalIP();
    void parseKeyInfo(const std::string& response);
    void fetchMessages();
    
public:
    AuthClient(const std::string& url);
    ~AuthClient();
    
    void setCredentials(const std::string& accId, const std::string& token);
    bool validateKey(const std::string& key);
    bool checkServer();
    
    std::string getLastError() const { return lastError; }
    std::string getHWID() const { return hwid; }
    std::string getIP() const { return localIp; }
    bool getIsAuthenticated() const { return isAuthenticated; }
    KeyInfo getKeyInfo() const { return keyInfo; }
    std::vector<Message> getMessages() const { return messages; }
};
