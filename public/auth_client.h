#pragma once
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

class AuthClient {
private:
    std::string serverUrl;
    std::string hwid;
    std::string localIp;
    std::string lastError;
    std::string accountId;
    std::string apiToken;
    
    std::string makeRequest(const std::string& endpoint, const std::string& jsonBody);
    std::string generateHWID();
    std::string getLocalIP();
    
public:
    AuthClient(const std::string& url = "http://localhost:3000");
    
    void setCredentials(const std::string& accId, const std::string& token);
    bool validateKey(const std::string& key);
    bool checkServer();
    
    std::string getLastError() const { return lastError; }
    std::string getHWID() const { return hwid; }
    std::string getIP() const { return localIp; }
};
