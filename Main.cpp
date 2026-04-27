#include "pch.h"
#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <vector>
#include <iomanip>
#include <wincred.h>
#include <wincrypt.h>
#define SECURITY_WIN32
#include <security.h>
#include <authz.h>
#include "MinHook.h"

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "authz.lib")

// ----------------------- ЛОГИРОВАНИЕ -----------------------
std::ofstream& GetLogFile() {
    static std::ofstream log("hooklog.txt", std::ios::app);
    return log;
}

std::mutex& GetLogMutex() {
    static std::mutex logMutex;
    return logMutex;
}

inline std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

inline void WriteLog(const std::string& msg) {
    auto& log = GetLogFile();
    auto& logMutex = GetLogMutex();
    std::lock_guard<std::mutex> lock(logMutex);
    log << msg << std::endl;
    log.flush();
}

inline void WriteLogW(const std::wstring& msg) {
    WriteLog(ws2s(msg));
}

inline std::string bin2hex(const unsigned char* data, size_t size) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        oss << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

// --- COMMON SIGNATURES ---

// Интернет/HTTP
typedef HINTERNET(WINAPI* pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI* pInternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* pHttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI* pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);

// Сравнение ключа
typedef int(__cdecl* pStrcmp)(const char*, const char*);
typedef int(__cdecl* pMemcmp)(const void*, const void*, size_t);

// UI
typedef UINT(WINAPI* pGetDlgItemTextA)(HWND, int, LPSTR, int);
typedef UINT(WINAPI* pGetDlgItemTextW)(HWND, int, LPWSTR, int);
typedef BOOL(WINAPI* pSetWindowTextA)(HWND, LPCSTR);
typedef BOOL(WINAPI* pSetWindowTextW)(HWND, LPCWSTR);

// Файлы
typedef BOOL(WINAPI* pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

// Крипто/WinAPI
typedef BOOL(WINAPI* pLogonUserA)(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
typedef BOOL(WINAPI* pLogonUserW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE);
typedef BOOL(WINAPI* pCredWriteA)(PCREDENTIALA, DWORD);
typedef BOOL(WINAPI* pCredWriteW)(PCREDENTIALW, DWORD);
typedef BOOL(WINAPI* pCryptAcquireContextA)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL(WINAPI* pCryptAcquireContextW)(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef BOOL(WINAPI* pCryptReleaseContext)(HCRYPTPROV, DWORD);
typedef BOOL(WINAPI* pCryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
typedef BOOL(WINAPI* pCryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
typedef BOOL(WINAPI* pCryptVerifySignature)(HCRYPTHASH, const BYTE*, DWORD, HCRYPTKEY, LPCSTR, DWORD);
typedef SECURITY_STATUS(WINAPI* pAcquireCredentialsHandleA)(
    LPSTR, LPSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
typedef SECURITY_STATUS(WINAPI* pAcquireCredentialsHandleW)(
    LPWSTR, LPWSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
typedef SECURITY_STATUS(WINAPI* pAcceptSecurityContext)(
    PCredHandle, PCtxtHandle, PSecBufferDesc, ULONG, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS(WINAPI* pInitializeSecurityContextA)(
    PCredHandle, PCtxtHandle, SEC_CHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS(WINAPI* pInitializeSecurityContextW)(
    PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS(WINAPI* pImpersonateSecurityContext)(PCtxtHandle);
typedef SECURITY_STATUS(WINAPI* pRevertSecurityContext)(PCtxtHandle);
typedef BOOL(WINAPI* pAuthzInitializeResourceManager)(DWORD, PFN_AUTHZ_DYNAMIC_ACCESS_CHECK, PFN_AUTHZ_COMPUTE_DYNAMIC_GROUPS, PFN_AUTHZ_FREE_DYNAMIC_GROUPS, PCWSTR, PAUTHZ_RESOURCE_MANAGER_HANDLE);
typedef BOOL(WINAPI* pAuthzAccessCheck)(DWORD, AUTHZ_CLIENT_CONTEXT_HANDLE, PAUTHZ_ACCESS_REQUEST, AUTHZ_AUDIT_EVENT_HANDLE, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR*, DWORD, PAUTHZ_ACCESS_REPLY, PAUTHZ_ACCESS_CHECK_RESULTS_HANDLE);

// --- HOOKED FUNCTION POINTERS ---
pInternetOpenUrlA   fpInternetOpenUrlA = NULL;
pInternetOpenUrlW   fpInternetOpenUrlW = NULL;
pHttpSendRequestA   fpHttpSendRequestA = NULL;
pHttpSendRequestW   fpHttpSendRequestW = NULL;
pInternetReadFile   fpInternetReadFile = NULL;
pWinHttpSendRequest fpWinHttpSendRequest = NULL;
pWinHttpReadData    fpWinHttpReadData = NULL;

pStrcmp             fpStrcmp = NULL;
pMemcmp             fpMemcmp = NULL;

pGetDlgItemTextA    fpGetDlgItemTextA = NULL;
pGetDlgItemTextW    fpGetDlgItemTextW = NULL;
pSetWindowTextA     fpSetWindowTextA = NULL;
pSetWindowTextW     fpSetWindowTextW = NULL;

pWriteFile          fpWriteFile = NULL;
pReadFile           fpReadFile = NULL;

pLogonUserA         fpLogonUserA = NULL;
pLogonUserW         fpLogonUserW = NULL;
pCredWriteA         fpCredWriteA = NULL;
pCredWriteW         fpCredWriteW = NULL;
pCryptAcquireContextA fpCryptAcquireContextA = NULL;
pCryptAcquireContextW fpCryptAcquireContextW = NULL;
pCryptReleaseContext fpCryptReleaseContext = NULL;
pCryptDecrypt       fpCryptDecrypt = NULL;
pCryptEncrypt       fpCryptEncrypt = NULL;
pCryptVerifySignature fpCryptVerifySignature = NULL;
pAcquireCredentialsHandleA fpAcquireCredentialsHandleA = NULL;
pAcquireCredentialsHandleW fpAcquireCredentialsHandleW = NULL;
pAcceptSecurityContext fpAcceptSecurityContext = NULL;
pInitializeSecurityContextA fpInitializeSecurityContextA = NULL;
pInitializeSecurityContextW fpInitializeSecurityContextW = NULL;
pImpersonateSecurityContext fpImpersonateSecurityContext = NULL;
pRevertSecurityContext fpRevertSecurityContext = NULL;
pAuthzInitializeResourceManager fpAuthzInitializeResourceManager = NULL;
pAuthzAccessCheck    fpAuthzAccessCheck = NULL;

// --- HOOKED FUNCTIONS (расширенное логирование) ---

// Интернет/HTTP
HINTERNET WINAPI Hooked_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    WriteLog("[HOOK] InternetOpenUrlA: " + std::string(lpszUrl ? lpszUrl : "(null)"));
    return fpInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}
HINTERNET WINAPI Hooked_InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    WriteLogW(L"[HOOK] InternetOpenUrlW: " + std::wstring(lpszUrl ? lpszUrl : L"(null)"));
    return fpInternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}
BOOL WINAPI Hooked_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength) {
    WriteLog("[HOOK] HttpSendRequestA");
    return fpHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}
BOOL WINAPI Hooked_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength) {
    WriteLogW(L"[HOOK] HttpSendRequestW");
    return fpHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}
BOOL WINAPI Hooked_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    WriteLog("[HOOK] InternetReadFile");
    return fpInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}
BOOL WINAPI Hooked_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    WriteLogW(L"[HOOK] WinHttpSendRequest");
    return fpWinHttpSendRequest(hRequest, pwszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}
BOOL WINAPI Hooked_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwBytesToRead, LPDWORD lpdwBytesRead) {
    WriteLog("[HOOK] WinHttpReadData");
    return fpWinHttpReadData(hRequest, lpBuffer, dwBytesToRead, lpdwBytesRead);
}

// Сравнение ключа
int __cdecl Hooked_Strcmp(const char* s1, const char* s2) {
    WriteLog("[HOOK] strcmp: " + std::string(s1 ? s1 : "(null)") + " vs " + std::string(s2 ? s2 : "(null)"));
    return fpStrcmp(s1, s2);
}
int __cdecl Hooked_Memcmp(const void* s1, const void* s2, size_t len) {
    std::ostringstream oss;
    oss << "[HOOK] memcmp, len=" << len;
    WriteLog(oss.str());
    return fpMemcmp(s1, s2, len);
}

// UI Ввод/отображение паролей и ключей
UINT WINAPI Hooked_GetDlgItemTextA(HWND hDlg, int nIDDlgItem, LPSTR lpString, int nMaxCount) {
    UINT result = fpGetDlgItemTextA(hDlg, nIDDlgItem, lpString, nMaxCount);
    WriteLog("[HOOK] GetDlgItemTextA (ID: " + std::to_string(nIDDlgItem) + "): " +
        (lpString ? std::string(lpString) : "<NULL>"));
    return result;
}
UINT WINAPI Hooked_GetDlgItemTextW(HWND hDlg, int nIDDlgItem, LPWSTR lpString, int nMaxCount) {
    UINT result = fpGetDlgItemTextW(hDlg, nIDDlgItem, lpString, nMaxCount);
    WriteLog("[HOOK] GetDlgItemTextW (ID: " + std::to_string(nIDDlgItem) + "): " +
        ws2s(lpString ? lpString : L"<NULL>"));
    return result;
}
BOOL WINAPI Hooked_SetWindowTextA(HWND hWnd, LPCSTR lpString) {
    WriteLog("[HOOK] SetWindowTextA: " + std::string(lpString ? lpString : "(null)"));
    return fpSetWindowTextA(hWnd, lpString);
}
BOOL WINAPI Hooked_SetWindowTextW(HWND hWnd, LPCWSTR lpString) {
    WriteLogW(L"[HOOK] SetWindowTextW: " + std::wstring(lpString ? lpString : L"(null)"));
    return fpSetWindowTextW(hWnd, lpString);
}

// Файлы (добавлена возможность логировать данные, если это строка; для бинарных файлов — раскомментируйте bin2hex)
BOOL WINAPI Hooked_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::ostringstream oss;
    oss << "[HOOK] WriteFile, bytes=" << nNumberOfBytesToWrite;
    // Для диагностики как строки (если lpBuffer похоже на текст):
    oss << ", data=\"";
    oss << std::string(reinterpret_cast<const char*>(lpBuffer), nNumberOfBytesToWrite);
    oss << "\"";
    // Для бинарника — раскомментируйте строку ниже:
    // oss << ", hex=" << bin2hex(reinterpret_cast<const unsigned char*>(lpBuffer), nNumberOfBytesToWrite);
    WriteLog(oss.str());
    return fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
BOOL WINAPI Hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL ret = fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    std::ostringstream oss;
    oss << "[HOOK] ReadFile, bytes=" << nNumberOfBytesToRead;
    if (lpBuffer && *lpNumberOfBytesRead > 0) {
        oss << ", data=\"";
        oss << std::string(reinterpret_cast<const char*>(lpBuffer), *lpNumberOfBytesRead);
        oss << "\"";
        // Для бинарника — раскомментируйте строку ниже:
        // oss << ", hex=" << bin2hex(reinterpret_cast<const unsigned char*>(lpBuffer), *lpNumberOfBytesRead);
    }
    WriteLog(oss.str());
    return ret;
}

// Крипто/WinAPI (auth/crypto/credentials)
BOOL WINAPI Hooked_LogonUserA(LPCSTR user, LPCSTR domain, LPCSTR pass, DWORD logonType, DWORD logonProvider, PHANDLE phToken) {
    WriteLog("[HOOK] LogonUserA: user=\"" + std::string(user ? user : "(null)") + "\" pass=\"" +
        std::string(pass ? pass : "(null)") + "\"");
    return fpLogonUserA(user, domain, pass, logonType, logonProvider, phToken);
}
BOOL WINAPI Hooked_LogonUserW(LPCWSTR user, LPCWSTR domain, LPCWSTR pass, DWORD logonType, DWORD logonProvider, PHANDLE phToken) {
    WriteLog("[HOOK] LogonUserW: user=\"" + ws2s(user ? user : L"(null)") + "\" pass=\"" +
        ws2s(pass ? pass : L"(null)") + "\"");
    return fpLogonUserW(user, domain, pass, logonType, logonProvider, phToken);
}
BOOL WINAPI Hooked_CredWriteA(PCREDENTIALA cred, DWORD flags) {
    WriteLog("[HOOK] CredWriteA");
    return fpCredWriteA(cred, flags);
}
BOOL WINAPI Hooked_CredWriteW(PCREDENTIALW cred, DWORD flags) {
    WriteLog("[HOOK] CredWriteW");
    return fpCredWriteW(cred, flags);
}
BOOL WINAPI Hooked_CryptAcquireContextA(HCRYPTPROV* phProv, LPCSTR pszContainer, LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
    WriteLog("[HOOK] CryptAcquireContextA");
    return fpCryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}
BOOL WINAPI Hooked_CryptAcquireContextW(HCRYPTPROV* phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
    WriteLogW(L"[HOOK] CryptAcquireContextW");
    return fpCryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}
BOOL WINAPI Hooked_CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
    WriteLog("[HOOK] CryptReleaseContext");
    return fpCryptReleaseContext(hProv, dwFlags);
}
BOOL WINAPI Hooked_CryptDecrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL bFinal, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    WriteLog("[HOOK] CryptDecrypt");
    return fpCryptDecrypt(key, hash, bFinal, dwFlags, pbData, pdwDataLen);
}
BOOL WINAPI Hooked_CryptEncrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL bFinal, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    WriteLog("[HOOK] CryptEncrypt");
    return fpCryptEncrypt(key, hash, bFinal, dwFlags, pbData, pdwDataLen, dwBufLen);
}
BOOL WINAPI Hooked_CryptVerifySignature(HCRYPTHASH hash, const BYTE* pbSignature, DWORD cbSignature, HCRYPTKEY hPubKey, LPCSTR sDescription, DWORD dwFlags) {
    WriteLog("[HOOK] CryptVerifySignature");
    return fpCryptVerifySignature(hash, pbSignature, cbSignature, hPubKey, sDescription, dwFlags);
}
SECURITY_STATUS WINAPI Hooked_AcquireCredentialsHandleA(
    LPSTR pszPrincipal, LPSTR pszPackage, ULONG fCredentialUse, PLUID pvLogonId, PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn, PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry) {
    WriteLog("[HOOK] AcquireCredentialsHandleA");
    return fpAcquireCredentialsHandleA(pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_AcquireCredentialsHandleW(
    LPWSTR pszPrincipal, LPWSTR pszPackage, ULONG fCredentialUse, PLUID pvLogonId, PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn, PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry) {
    WriteLogW(L"[HOOK] AcquireCredentialsHandleW");
    return fpAcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput,
    ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry) {
    WriteLog("[HOOK] AcceptSecurityContext");
    return fpAcceptSecurityContext(phCredential, phContext, pInput, fContextReq, TargetDataRep, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_InitializeSecurityContextA(PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR* pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput,
    ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry) {
    WriteLog("[HOOK] InitializeSecurityContextA");
    return fpInitializeSecurityContextA(phCredential, phContext, pszTargetName, fContextReq, Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR* pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput,
    ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry) {
    WriteLogW(L"[HOOK] InitializeSecurityContextW");
    return fpInitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_ImpersonateSecurityContext(PCtxtHandle phContext) {
    WriteLog("[HOOK] ImpersonateSecurityContext");
    return fpImpersonateSecurityContext(phContext);
}
SECURITY_STATUS WINAPI Hooked_RevertSecurityContext(PCtxtHandle phContext) {
    WriteLog("[HOOK] RevertSecurityContext");
    return fpRevertSecurityContext(phContext);
}
BOOL WINAPI Hooked_AuthzInitializeResourceManager(DWORD flags, PFN_AUTHZ_DYNAMIC_ACCESS_CHECK fn1, PFN_AUTHZ_COMPUTE_DYNAMIC_GROUPS fn2, PFN_AUTHZ_FREE_DYNAMIC_GROUPS fn3, PCWSTR sz, PAUTHZ_RESOURCE_MANAGER_HANDLE handle) {
    WriteLogW(L"[HOOK] AuthzInitializeResourceManager");
    return fpAuthzInitializeResourceManager(flags, fn1, fn2, fn3, sz, handle);
}
BOOL WINAPI Hooked_AuthzAccessCheck(DWORD flags, AUTHZ_CLIENT_CONTEXT_HANDLE ctx, PAUTHZ_ACCESS_REQUEST req, AUTHZ_AUDIT_EVENT_HANDLE audit, PSECURITY_DESCRIPTOR sd, PSECURITY_DESCRIPTOR* pSidArray, DWORD count, PAUTHZ_ACCESS_REPLY reply, PAUTHZ_ACCESS_CHECK_RESULTS_HANDLE result) {
    WriteLog("[HOOK] AuthzAccessCheck");
    return fpAuthzAccessCheck(flags, ctx, req, audit, sd, pSidArray, count, reply, result);
}

// --- INIT HOOKS ---
void SetHooks() {
    MH_Initialize();

    // Интернет/HTTP
    MH_CreateHook(&InternetOpenUrlA, &Hooked_InternetOpenUrlA, reinterpret_cast<LPVOID*>(&fpInternetOpenUrlA));
    MH_CreateHook(&InternetOpenUrlW, &Hooked_InternetOpenUrlW, reinterpret_cast<LPVOID*>(&fpInternetOpenUrlW));
    MH_CreateHook(&HttpSendRequestA, &Hooked_HttpSendRequestA, reinterpret_cast<LPVOID*>(&fpHttpSendRequestA));
    MH_CreateHook(&HttpSendRequestW, &Hooked_HttpSendRequestW, reinterpret_cast<LPVOID*>(&fpHttpSendRequestW));
    MH_CreateHook(&InternetReadFile, &Hooked_InternetReadFile, reinterpret_cast<LPVOID*>(&fpInternetReadFile));
    MH_CreateHook(&WinHttpSendRequest, &Hooked_WinHttpSendRequest, reinterpret_cast<LPVOID*>(&fpWinHttpSendRequest));
    MH_CreateHook(&WinHttpReadData, &Hooked_WinHttpReadData, reinterpret_cast<LPVOID*>(&fpWinHttpReadData));

    // Сравнение
    MH_CreateHook(&strcmp, &Hooked_Strcmp, reinterpret_cast<LPVOID*>(&fpStrcmp));
    MH_CreateHook(&memcmp, &Hooked_Memcmp, reinterpret_cast<LPVOID*>(&fpMemcmp));

    // UI
    MH_CreateHook(&GetDlgItemTextA, &Hooked_GetDlgItemTextA, reinterpret_cast<LPVOID*>(&fpGetDlgItemTextA));
    MH_CreateHook(&GetDlgItemTextW, &Hooked_GetDlgItemTextW, reinterpret_cast<LPVOID*>(&fpGetDlgItemTextW));
    MH_CreateHook(&SetWindowTextA, &Hooked_SetWindowTextA, reinterpret_cast<LPVOID*>(&fpSetWindowTextA));
    MH_CreateHook(&SetWindowTextW, &Hooked_SetWindowTextW, reinterpret_cast<LPVOID*>(&fpSetWindowTextW));

    // Файлы
    MH_CreateHook(&WriteFile, &Hooked_WriteFile, reinterpret_cast<LPVOID*>(&fpWriteFile));
    MH_CreateHook(&ReadFile, &Hooked_ReadFile, reinterpret_cast<LPVOID*>(&fpReadFile));

    // Крипто/авторизация
    MH_CreateHook(&LogonUserA, &Hooked_LogonUserA, reinterpret_cast<LPVOID*>(&fpLogonUserA));
    MH_CreateHook(&LogonUserW, &Hooked_LogonUserW, reinterpret_cast<LPVOID*>(&fpLogonUserW));
    MH_CreateHook(&CredWriteA, &Hooked_CredWriteA, reinterpret_cast<LPVOID*>(&fpCredWriteA));
    MH_CreateHook(&CredWriteW, &Hooked_CredWriteW, reinterpret_cast<LPVOID*>(&fpCredWriteW));
    MH_CreateHook(&CryptAcquireContextA, &Hooked_CryptAcquireContextA, reinterpret_cast<LPVOID*>(&fpCryptAcquireContextA));
    MH_CreateHook(&CryptAcquireContextW, &Hooked_CryptAcquireContextW, reinterpret_cast<LPVOID*>(&fpCryptAcquireContextW));
    MH_CreateHook(&CryptReleaseContext, &Hooked_CryptReleaseContext, reinterpret_cast<LPVOID*>(&fpCryptReleaseContext));
    MH_CreateHook(&CryptDecrypt, &Hooked_CryptDecrypt, reinterpret_cast<LPVOID*>(&fpCryptDecrypt));
    MH_CreateHook(&CryptEncrypt, &Hooked_CryptEncrypt, reinterpret_cast<LPVOID*>(&fpCryptEncrypt));
    MH_CreateHook(&CryptVerifySignature, &Hooked_CryptVerifySignature, reinterpret_cast<LPVOID*>(&fpCryptVerifySignature));

    MH_CreateHook(&AcquireCredentialsHandleA, &Hooked_AcquireCredentialsHandleA, reinterpret_cast<LPVOID*>(&fpAcquireCredentialsHandleA));
    MH_CreateHook(&AcquireCredentialsHandleW, &Hooked_AcquireCredentialsHandleW, reinterpret_cast<LPVOID*>(&fpAcquireCredentialsHandleW));
    MH_CreateHook(&AcceptSecurityContext, &Hooked_AcceptSecurityContext, reinterpret_cast<LPVOID*>(&fpAcceptSecurityContext));
    MH_CreateHook(&InitializeSecurityContextA, &Hooked_InitializeSecurityContextA, reinterpret_cast<LPVOID*>(&fpInitializeSecurityContextA));
    MH_CreateHook(&InitializeSecurityContextW, &Hooked_InitializeSecurityContextW, reinterpret_cast<LPVOID*>(&fpInitializeSecurityContextW));
    MH_CreateHook(&ImpersonateSecurityContext, &Hooked_ImpersonateSecurityContext, reinterpret_cast<LPVOID*>(&fpImpersonateSecurityContext));
    MH_CreateHook(&RevertSecurityContext, &Hooked_RevertSecurityContext, reinterpret_cast<LPVOID*>(&fpRevertSecurityContext));
    MH_CreateHook(&AuthzInitializeResourceManager, &Hooked_AuthzInitializeResourceManager, reinterpret_cast<LPVOID*>(&fpAuthzInitializeResourceManager));
    MH_CreateHook(&AuthzAccessCheck, &Hooked_AuthzAccessCheck, reinterpret_cast<LPVOID*>(&fpAuthzAccessCheck));

    // Commit hooks
    MH_EnableHook(MH_ALL_HOOKS);
}

// --- DLLMAIN Entry ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        SetHooks();
    }
    return TRUE;
}
