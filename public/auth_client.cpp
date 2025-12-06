#include "auth_client.h"
#include <sstream>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <cstring>
#include <ctime>

#ifdef _WIN32

std::string AuthClient::generateHWID() {
    std::string hwid = "";
    std::vector<std::string> components;
    
    FILE* pipe = _popen("wmic path win32_computersystemproduct get uuid 2>nul", "r");
    if (pipe) {
        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        
        size_t pos = result.find('\n');
        if (pos != std::string::npos) {
            std::string line = result.substr(pos + 1);
            line.erase(0, line.find_first_not_of(" \t\n\r"));
            line.erase(line.find_last_not_of(" \t\n\r") + 1);
            if (!line.empty() && line.length() > 10) {
                components.push_back("UUID:" + line);
            }
        }
    }
    
    pipe = _popen("wmic bios get serialnumber 2>nul | findstr /v \"SerialNumber\"", "r");
    if (pipe) {
        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        
        result.erase(0, result.find_first_not_of(" \t\n\r"));
        result.erase(result.find_last_not_of(" \t\n\r") + 1);
        if (!result.empty() && result != "To be filled by O.E.M." && result.length() > 3) {
            components.push_back("BIOS:" + result);
        }
    }
    
    pipe = _popen("wmic cpu get processorid 2>nul | findstr /v \"ProcessorId\"", "r");
    if (pipe) {
        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        
        result.erase(0, result.find_first_not_of(" \t\n\r"));
        result.erase(result.find_last_not_of(" \t\n\r") + 1);
        if (!result.empty() && result.length() > 5) {
            components.push_back("CPU:" + result);
        }
    }
    
    pipe = _popen("wmic baseboard get serialnumber 2>nul | findstr /v \"SerialNumber\"", "r");
    if (pipe) {
        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        
        result.erase(0, result.find_first_not_of(" \t\n\r"));
        result.erase(result.find_last_not_of(" \t\n\r") + 1);
        if (!result.empty() && result != "To be filled by O.E.M." && result.length() > 3) {
            components.push_back("MB:" + result);
        }
    }
    
    pipe = _popen("wmic nic where \"NetEnabled=true\" get macaddress 2>nul | findstr /v \"MACAddress\" | findstr /v \"^$\"", "r");
    if (pipe) {
        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
            break;
        }
        _pclose(pipe);
        
        result.erase(0, result.find_first_not_of(" \t\n\r"));
        result.erase(result.find_last_not_of(" \t\n\r") + 1);
        if (!result.empty() && result.length() > 10) {
            components.push_back("MAC:" + result);
        }
    }
    
    pipe = _popen("vol C: 2>nul | findstr \"Serial\"", "r");
    if (pipe) {
        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        
        size_t pos = result.find("is ");
        if (pos != std::string::npos) {
            std::string serial = result.substr(pos + 3);
            serial.erase(0, serial.find_first_not_of(" \t\n\r"));
            serial.erase(serial.find_last_not_of(" \t\n\r") + 1);
            if (!serial.empty()) {
                components.push_back("VOL:" + serial);
            }
        }
    }
    
    if (components.empty()) {
        return "UNKNOWN";
    }
    
    for (size_t i = 0; i < components.size(); i++) {
        if (i > 0) hwid += "-";
        hwid += components[i];
    }
    
    if (hwid.length() > 200) {
        hwid = "";
        for (size_t i = 0; i < components.size() && i < 5; i++) {
            if (i > 0) hwid += "-";
            std::string comp = components[i];
            size_t colon = comp.find(':');
            if (colon != std::string::npos) {
                std::string value = comp.substr(colon + 1);
                if (value.length() > 8) {
                    value = value.substr(0, 8);
                }
                hwid += comp.substr(0, colon + 1) + value;
            } else {
                hwid += comp.substr(0, 12);
            }
        }
    }
    
    return hwid;
}

std::string AuthClient::getLocalIP() {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    std::string publicIP = "Unknown";
    
    try {
        hSession = WinHttpOpen(L"Astreon/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return publicIP;
        
        WinHttpSetTimeouts(hSession, 8000, 8000, 8000, 8000);
        
        hConnect = WinHttpConnect(hSession, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return publicIP;
        }
        
        hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return publicIP;
        }
        
        BOOL sent = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, NULL);
        
        if (!sent) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return publicIP;
        }
        
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return publicIP;
        }
        
        DWORD bytesAvailable, bytesRead;
        char buffer[256];
        std::string response;
        
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) break;
            if (bytesAvailable == 0) break;
            if (!WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) break;
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                response += buffer;
            }
        } while (bytesRead > 0);
        
        if (!response.empty()) {
            response.erase(0, response.find_first_not_of(" \t\n\r"));
            response.erase(response.find_last_not_of(" \t\n\r") + 1);
            publicIP = response;
        }
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
    }
    catch (...) {
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }
    
    return publicIP;
}

std::string AuthClient::makeRequest(const std::string& endpoint, const std::string& jsonBody) {
    if (!AuthSecurity::TimeValidator::isValidRequest()) {
        return "ERROR: Invalid request timing";
    }
    
    if (AuthSecurity::AntiHook::checkCriticalFunctions()) {
        return "ERROR: Security violation detected";
    }
    
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    std::string response;
    
    try {
        hSession = WinHttpOpen(L"KeyAuth",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return "ERROR: Failed to init";
        
        WinHttpSetTimeouts(hSession, 5000, 10000, 10000, 10000);
        
        std::string encKey = KeyAuth::encryption::hash(hwid + localIp);
        std::string url = KeyAuth::encryption::decrypt(serverUrl, encKey);
        bool isHttps = url.find("https://") == 0;
        std::string host;
        INTERNET_PORT port;
        
        if (isHttps) {
            url = url.substr(8);
            port = INTERNET_DEFAULT_HTTPS_PORT;
        } else if (url.find("http://") == 0) {
            url = url.substr(7);
            port = INTERNET_DEFAULT_HTTP_PORT;
        } else {
            port = INTERNET_DEFAULT_HTTP_PORT;
        }
        
        size_t slashPos = url.find('/');
        if (slashPos != std::string::npos) {
            host = url.substr(0, slashPos);
        } else {
            host = url;
        }
        
        size_t colonPos = host.find(':');
        if (colonPos != std::string::npos) {
            std::string portStr = host.substr(colonPos + 1);
            port = (INTERNET_PORT)atoi(portStr.c_str());
            host = host.substr(0, colonPos);
        }
        
        std::wstring wHost(host.begin(), host.end());
        
        hConnect = WinHttpConnect(hSession, wHost.c_str(), port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "ERROR: Failed to connect";
        }
        
        std::wstring path = L"/";
        path += std::wstring(endpoint.begin(), endpoint.end());
        
        DWORD flags = 0;
        if (isHttps) {
            flags = WINHTTP_FLAG_SECURE;
        }
        
        hRequest = WinHttpOpenRequest(hConnect, 
            jsonBody.empty() ? L"GET" : L"POST",
            path.c_str(), NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "ERROR: Failed to create request";
        }
        
        std::wstring headers = L"Content-Type: application/json\r\n";
        
        BOOL sent = WinHttpSendRequest(hRequest,
            headers.c_str(), (DWORD)-1,
            jsonBody.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)jsonBody.c_str(),
            jsonBody.empty() ? 0 : (DWORD)jsonBody.length(),
            jsonBody.empty() ? 0 : (DWORD)jsonBody.length(),
            NULL);
        
        if (!sent) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "ERROR: Failed to send request";
        }
        
        DWORD receiveTimeout = 10000;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &receiveTimeout, sizeof(receiveTimeout));
        
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD error = GetLastError();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (error == ERROR_WINHTTP_TIMEOUT) {
                return "ERROR: Request timeout";
            }
            return "ERROR: Failed to receive response";
        }
        
        DWORD bytesAvailable, bytesRead;
        char buffer[4096];
        
        do {
            if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) break;
            if (bytesAvailable == 0) break;
            if (!WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) break;
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                response += buffer;
            }
        } while (bytesRead > 0);
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return response;
    }
    catch (...) {
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
        return "ERROR: Exception";
    }
}

#else
std::string AuthClient::generateHWID() { return "UNKNOWN"; }
std::string AuthClient::getLocalIP() { return "Unknown"; }
std::string AuthClient::makeRequest(const std::string&, const std::string&) { return "ERROR: Windows only"; }
#endif

AuthClient::AuthClient(const std::string& url) : serverUrl(url), isAuthenticated(false) {
    hwid = generateHWID();
    localIp = getLocalIP();
    accountId = "";
    apiToken = "";
    validatedKey = "";
    
    std::string encKey = KeyAuth::encryption::hash(hwid + localIp);
    serverUrl = KeyAuth::encryption::encrypt(serverUrl, encKey);
}

AuthClient::~AuthClient() {
}

void AuthClient::setCredentials(const std::string& accId, const std::string& token) {
    if (AuthSecurity::AntiHook::checkCriticalFunctions()) {
        return;
    }
    
    std::string encKey = KeyAuth::encryption::hash(hwid + localIp);
    accountId = KeyAuth::encryption::encrypt(accId, encKey);
    apiToken = KeyAuth::encryption::encrypt(token, encKey);
    
    AuthSecurity::MemoryProtection::secureClear(encKey);
}

bool AuthClient::checkServer() {
    lastError = "";
    std::string response = makeRequest("api/health", "");
    
    if (response.empty() || response.find("ERROR:") != std::string::npos) {
        if (response.empty()) {
            lastError = "Server timeout or offline";
        } else {
            lastError = response;
        }
        return false;
    }
    
    return response.find("\"success\":true") != std::string::npos;
}

bool AuthClient::validateKey(const std::string& key) {
    lastError = "";
    
    if (key.empty()) {
        lastError = "Invalid key";
        return false;
    }
    
    if (!AuthSecurity::TimeValidator::isValidRequest()) {
        lastError = "System time tampering detected";
        return false;
    }
    
    std::string encKey = KeyAuth::encryption::hash(hwid + localIp);
    std::string decAccountId = KeyAuth::encryption::decrypt(accountId, encKey);
    std::string decApiToken = KeyAuth::encryption::decrypt(apiToken, encKey);
    
    std::stringstream json;
    json << "{\"key\":\"" << key << "\",\"hwid\":\"" << hwid << "\",\"ip\":\"" << localIp << "\"";
    
    if (!decAccountId.empty() && !decApiToken.empty()) {
        json << ",\"accountId\":\"" << decAccountId << "\",\"apiToken\":\"" << decApiToken << "\"";
    }
    
    json << "}";
    
    std::string requestData = json.str();
    
    std::string response = makeRequest("api/validate", requestData);
    
    AuthSecurity::MemoryProtection::secureClear(decAccountId);
    AuthSecurity::MemoryProtection::secureClear(decApiToken);
    AuthSecurity::MemoryProtection::secureClear(encKey);
    AuthSecurity::MemoryProtection::secureClear(requestData);
    
    if (response.empty()) {
        lastError = "Connection timeout. Server may be offline.";
        return false;
    }
    
    if (response.find("ERROR:") != std::string::npos) {
        lastError = response;
        return false;
    }
    
    if (response.find("\"success\":true") != std::string::npos) {
        isAuthenticated = true;
        validatedKey = key;
        return true;
    }
    
    size_t msgPos = response.find("\"message\":\"");
    if (msgPos != std::string::npos) {
        msgPos += 11;
        size_t msgEnd = response.find("\"", msgPos);
        if (msgEnd != std::string::npos) {
            lastError = response.substr(msgPos, msgEnd - msgPos);
        }
    }
    
    if (lastError.empty()) {
        lastError = "Invalid key";
    }
    
    return false;
}
