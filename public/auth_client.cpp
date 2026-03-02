#include "auth_client.h"
#include <sstream>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <cstring>
#include <regex>

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>

std::string SecureConnection::generateHWID() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return "UNKNOWN";
    }

    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        CloseHandle(hToken);
        return "UNKNOWN";
    }

    std::vector<BYTE> buffer(size);
    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    if (!GetTokenInformation(hToken, TokenUser, tokenUser, size, &size)) {
        CloseHandle(hToken);
        return "UNKNOWN";
    }

    LPSTR sidString = nullptr;
    if (!ConvertSidToStringSidA(tokenUser->User.Sid, &sidString) || !sidString) {
        CloseHandle(hToken);
        return "UNKNOWN";
    }

    std::string hwid(sidString);
    LocalFree(sidString);
    CloseHandle(hToken);

    if (hwid.empty()) {
        return "UNKNOWN";
    }

    return hwid;
}

std::string SecureConnection::getLocalIP() {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    std::string publicIP = "Unknown";
    
    try {
        hSession = WinHttpOpen(L"Auth/1.0",
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

std::string SecureConnection::makeRequest(const std::string& endpoint, const std::string& jsonBody) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    std::string response;
    
    try {
        hSession = WinHttpOpen(L"SecureConnection",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return "ERROR: Failed to init";
        
        WinHttpSetTimeouts(hSession, 5000, 10000, 10000, 10000);
        
        std::string url = serverUrl;
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
std::string SecureConnection::generateHWID() { return "UNKNOWN"; }
std::string SecureConnection::getLocalIP() { return "Unknown"; }
std::string SecureConnection::makeRequest(const std::string&, const std::string&) { return "ERROR: Windows only"; }
#endif

SecureConnection::SecureConnection(const std::string& url) : serverUrl(url), isAuthenticated(false) {
    hwid = generateHWID();
    localIp = getLocalIP();
    accountId = "";
    apiToken = "";
    validatedKey = "";
    keyInfo = KeyInfo();
    messages.clear();
}

SecureConnection::~SecureConnection() {
}

void SecureConnection::setCredentials(const std::string& accId, const std::string& token) {
    accountId = accId;
    apiToken = token;
}

bool SecureConnection::checkServer() {
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

std::string SecureConnection::checkForUpdates(const std::string& currentVersion) {
    std::string response = makeRequest("api/updates/check", "");
    
    if (response.empty() || response.find("ERROR:") != std::string::npos) {
        return ""; // No update info available
    }
    
    if (response.find("\"success\":true") == std::string::npos) {
        return "";
    }
    
    return response;
}

bool SecureConnection::validateKey(const std::string& key) {
    lastError = "";
    
    if (key.empty()) {
        lastError = "Invalid key";
        return false;
    }
    
    std::stringstream json;
    json << "{\"key\":\"" << key << "\",\"hwid\":\"" << hwid << "\",\"ip\":\"" << localIp << "\"";
    
    if (!accountId.empty() && !apiToken.empty()) {
        json << ",\"accountId\":\"" << accountId << "\",\"apiToken\":\"" << apiToken << "\"";
    }
    
    json << "}";
    
    std::string requestData = json.str();
    
    std::string endpoint = "api/validate";
    std::string response = makeRequest(endpoint, requestData);
    
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
        
        parseKeyInfo(response);
        
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

std::string extractJsonString(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\":\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) {
        searchKey = "\"" + key + "\":";
        pos = json.find(searchKey);
        if (pos == std::string::npos) return "";
        pos += searchKey.length();
        while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
        if (pos >= json.length()) return "";
        
        if (json.substr(pos, 4) == "null") return "";
        
        size_t end = pos;
        while (end < json.length() && json[end] != ',' && json[end] != '}' && json[end] != '\n') end++;
        std::string value = json.substr(pos, end - pos);
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
        return value;
    }
    pos += searchKey.length();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

void SecureConnection::parseKeyInfo(const std::string& response) {
    keyInfo = KeyInfo();
    
    size_t dataPos = response.find("\"data\":{");
    if (dataPos == std::string::npos) {
        keyInfo.isValid = false;
        return;
    }
    
    size_t dataStart = response.find("{", dataPos);
    if (dataStart == std::string::npos) {
        keyInfo.isValid = false;
        return;
    }
    
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
    
    keyInfo.duration = extractJsonString(dataJson, "duration");
    keyInfo.amount = extractJsonString(dataJson, "amount");
    keyInfo.expiresAt = extractJsonString(dataJson, "expiresAt");
    keyInfo.timeRemaining = extractJsonString(dataJson, "timeRemaining");
    
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

void SecureConnection::fetchMessages() {
    messages.clear();
    
    std::string response = makeRequest("api/messages", "");
    
    if (response.empty() || response.find("ERROR:") != std::string::npos) {
        return;
    }
    
    if (response.find("\"success\":true") == std::string::npos) {
        return;
    }
    
    size_t messagesPos = response.find("\"messages\":[");
    if (messagesPos == std::string::npos) {
        return;
    }
    
    size_t arrayStart = response.find("[", messagesPos);
    if (arrayStart == std::string::npos) {
        return;
    }
    
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
    
    size_t msgPos = 0;
    while ((msgPos = messagesJson.find("{", msgPos)) != std::string::npos) {
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
