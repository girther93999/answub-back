#pragma once
#include <string>
#include <thread>
#include <vector>

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

// ==========================================
// REAL CLIENT (Obfuscated Name)
// ==========================================
class SecureConnection {
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
    SecureConnection(const std::string& url);
    ~SecureConnection();
    
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

// ==========================================
// FAKE HONEYPOT (KeyAuth struct match)
// ==========================================
namespace KeyAuth {
    class api {
    public:
        std::string name, ownerid, secret, version, url;
        
        api(const std::string& name, const std::string& ownerid, const std::string& secret, const std::string& version, const std::string& url) 
            : name(name), ownerid(ownerid), secret(secret), version(version), url(url) {}
            
        void init() {
            // Fake initialization
            Sleep(50);
        }
        
        void license(const std::string& key) {
            // Fake license check
            Sleep(100);
        }
        
        void login(const std::string& username, const std::string& password) {
            // Fake login check
            Sleep(100);
        }
        
        void check() {
            // Fake check
            Sleep(30);
        }
        
        void log(const std::string& msg) {
            // Fake logging
        }
    };
}
