#include "auth_client.h"
#include <sstream>
#include <cstdlib>
#include <regex>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <cstring>
#include <ctime>

#ifdef _WIN32

std::string AuthClient::generateHWID() {
    std::string hwid = "";
    
    // Get CPU Processor ID using PowerShell
    FILE* pipe = _popen("powershell -command \"(Get-CimInstance Win32_Processor).ProcessorId\"", "r");
    if (pipe) {
        char buffer[256];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        _pclose(pipe);
        
        // Trim whitespace
        result.erase(0, result.find_first_not_of(" \t\n\r"));
        result.erase(result.find_last_not_of(" \t\n\r") + 1);
        
        if (!result.empty() && result.length() > 5) {
            hwid = result;
        }
    }
    
    // If we couldn't get the ProcessorId, return UNKNOWN
    if (hwid.empty()) {
        return "UNKNOWN";
    }
    
    return hwid;
}

std::string AuthClient::getLocalIP() {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    std::string publicIP = "Unknown";
    
    try {
        hSession = WinHttpOpen(L"Artic/1.0",
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
    keyInfo = KeyInfo();
    messages.clear();
    
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
        
        // Parse key info from response
        parseKeyInfo(response);
        
        // Fetch messages after successful validation
        fetchMessages();
        
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

// Helper function to extract JSON string value
std::string extractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) {
        // Try without quotes (for numbers/null)
        searchKey = "\"" + key + "\":";
        pos = json.find(searchKey);
        if (pos == std::string::npos) return "";
        pos += searchKey.length();
        // Skip whitespace
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        if (pos >= json.length()) return "";
        
        // Check if it's null
        if (json.substr(pos, 4) == "null") return "";
        
        // Extract number or value
        size_t end = pos;
        while (end < json.length() && json[end] != ',' && json[end] != '}' && json[end] != '\n') end++;
        std::string value = json.substr(pos, end - pos);
        // Remove trailing whitespace
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
        return value;
    }
    pos += searchKey.length();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

void AuthClient::parseKeyInfo(const std::string& response) {
    keyInfo = KeyInfo();
    
    // Find "data" object in JSON
    size_t dataPos = response.find("\"data\":{");
    if (dataPos == std::string::npos) {
        keyInfo.isValid = false;
        return;
    }
    
    // Extract data object (simplified JSON parsing)
    size_t dataStart = response.find("{", dataPos);
    if (dataStart == std::string::npos) {
        keyInfo.isValid = false;
        return;
    }
    
    // Find matching closing brace
    int braceCount = 0;
    size_t dataEnd = dataStart;
    for (size_t i = dataStart; i < response.length(); i++) {
        if (response[i] == '{') braceCount++;
        if (response[i] == '}') {
            braceCount--;
            if (braceCount == 0) {
                dataEnd = i + 1;
                break;
            }
        }
    }
    
    std::string dataJson = response.substr(dataStart, dataEnd - dataStart);
    
    // Extract fields
    keyInfo.duration = extractJsonString(dataJson, "duration");
    keyInfo.amount = extractJsonString(dataJson, "amount");
    keyInfo.expiresAt = extractJsonString(dataJson, "expiresAt");
    keyInfo.timeRemaining = extractJsonString(dataJson, "timeRemaining");
    
    // Parse timeRemainingSeconds
    std::string timeRemainingStr = extractJsonString(dataJson, "timeRemainingSeconds");
    if (!timeRemainingStr.empty()) {
        try {
            keyInfo.timeRemainingSeconds = std::stoi(timeRemainingStr);
        } catch (...) {
            keyInfo.timeRemainingSeconds = 0;
        }
    }
    
    keyInfo.hwid = extractJsonString(dataJson, "hwid");
    keyInfo.ip = extractJsonString(dataJson, "ip");
    keyInfo.usedAt = extractJsonString(dataJson, "usedAt");
    keyInfo.createdAt = extractJsonString(dataJson, "createdAt");
    keyInfo.isValid = true;
}

void AuthClient::fetchMessages() {
    messages.clear();
    
    std::string response = makeRequest("api/messages", "");
    
    if (response.empty() || response.find("ERROR:") != std::string::npos) {
        return; // Silently fail - messages are optional
    }
    
    if (response.find("\"success\":true") == std::string::npos) {
        return;
    }
    
    // Find "messages" array
    size_t messagesPos = response.find("\"messages\":[");
    if (messagesPos == std::string::npos) {
        return;
    }
    
    size_t arrayStart = response.find("[", messagesPos);
    if (arrayStart == std::string::npos) {
        return;
    }
    
    // Find matching closing bracket
    int bracketCount = 0;
    size_t arrayEnd = arrayStart;
    for (size_t i = arrayStart; i < response.length(); i++) {
        if (response[i] == '[') bracketCount++;
        if (response[i] == ']') {
            bracketCount--;
            if (bracketCount == 0) {
                arrayEnd = i + 1;
                break;
            }
        }
    }
    
    std::string messagesJson = response.substr(arrayStart, arrayEnd - arrayStart);
    
    // Parse each message (simplified - find each message object)
    size_t msgPos = 0;
    while ((msgPos = messagesJson.find("{", msgPos)) != std::string::npos) {
        // Find matching closing brace for this message
        int braceCount = 0;
        size_t msgEnd = msgPos;
        for (size_t i = msgPos; i < messagesJson.length(); i++) {
            if (messagesJson[i] == '{') braceCount++;
            if (messagesJson[i] == '}') {
                braceCount--;
                if (braceCount == 0) {
                    msgEnd = i + 1;
                    break;
                }
            }
        }
        
        std::string msgJson = messagesJson.substr(msgPos, msgEnd - msgPos);
        
        Message msg;
        msg.id = extractJsonString(msgJson, "id");
        msg.title = extractJsonString(msgJson, "title");
        msg.content = extractJsonString(msgJson, "content");
        msg.type = extractJsonString(msgJson, "type");
        msg.createdAt = extractJsonString(msgJson, "createdAt");
        msg.isValid = !msg.id.empty() && !msg.title.empty();
        
        if (msg.isValid) {
            messages.push_back(msg);
        }
        
        msgPos = msgEnd;
    }
}
