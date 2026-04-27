#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <shlwapi.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <wincred.h>
#include <wincrypt.h>
#include <security.h>
#include <authz.h>
#include "MinHook.h"

// --- COMMON SIGNATURES ---

// Интернет/HTTP
typedef HINTERNET(WINAPI *pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET(WINAPI *pInternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *pHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI *pHttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
typedef BOOL(WINAPI *pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI *pWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *pWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);

// Сравнение ключа
typedef int(__cdecl *pStrcmp)(const char*, const char*);
typedef int(__cdecl *pMemcmp)(const void*, const void*, size_t);

// UI
typedef UINT(WINAPI *pGetDlgItemTextA)(HWND, int, LPSTR, int);
typedef UINT(WINAPI *pGetDlgItemTextW)(HWND, int, LPWSTR, int);
typedef BOOL(WINAPI *pSetWindowTextA)(HWND, LPCSTR);
typedef BOOL(WINAPI *pSetWindowTextW)(HWND, LPCWSTR);

// Файлы
typedef BOOL(WINAPI *pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

// Крипто/WinAPI
typedef BOOL(WINAPI *pLogonUserA)(LPCSTR, LPCSTR, LPCSTR, DWORD, DWORD, PHANDLE);
typedef BOOL(WINAPI *pLogonUserW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE);
typedef BOOL(WINAPI *pCredWriteA)(PCREDENTIALA, DWORD);
typedef BOOL(WINAPI *pCredWriteW)(PCREDENTIALW, DWORD);
typedef BOOL(WINAPI *pCryptAcquireContextA)(HCRYPTPROV_PTR, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL(WINAPI *pCryptAcquireContextW)(HCRYPTPROV_PTR, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef BOOL(WINAPI *pCryptReleaseContext)(HCRYPTPROV, DWORD);
typedef BOOL(WINAPI *pCryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
typedef BOOL(WINAPI *pCryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
typedef BOOL(WINAPI *pCryptVerifySignature)(HCRYPTHASH, const BYTE*, DWORD, HCRYPTKEY, LPCSTR, DWORD);
typedef SECURITY_STATUS(WINAPI *pAcquireCredentialsHandleA)(
    LPSTR, LPSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
typedef SECURITY_STATUS(WINAPI *pAcquireCredentialsHandleW)(
    LPWSTR, LPWSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
typedef SECURITY_STATUS(WINAPI *pAcceptSecurityContext)(
    PCredHandle, PCtxtHandle, PSecBufferDesc, ULONG, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS(WINAPI *pInitializeSecurityContextA)(
    PCredHandle, PCtxtHandle, SEC_CHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS(WINAPI *pInitializeSecurityContextW)(
    PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS(WINAPI *pImpersonateSecurityContext)(PCtxtHandle);
typedef SECURITY_STATUS(WINAPI *pRevertSecurityContext)(PCtxtHandle);
typedef BOOL(WINAPI *pAuthzInitializeResourceManager)(DWORD, PFN_AUTHZ_DYNAMIC_ACCESS_CHECK, PFN_AUTHZ_COMPUTE_DYNAMIC_GROUPS, PFN_AUTHZ_FREE_DYNAMIC_GROUPS, PCWSTR, PAUTHZ_RESOURCE_MANAGER_HANDLE);
typedef BOOL(WINAPI *pAuthzAccessCheck)(DWORD, AUTHZ_CLIENT_CONTEXT_HANDLE, PAUTHZ_ACCESS_REQUEST, AUTHZ_AUDIT_EVENT_HANDLE, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR*, DWORD, PAUTHZ_ACCESS_REPLY, PAUTHZ_ACCESS_CHECK_RESULTS_HANDLE);

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

// --- HOOKED FUNCTIONS (diagnostic logging only) ---

// Интернет/HTTP
HINTERNET WINAPI Hooked_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    std::cout << "[HOOK] InternetOpenUrlA: " << (lpszUrl?lpszUrl:"(null)") << std::endl;
    return fpInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}
HINTERNET WINAPI Hooked_InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders,
    DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    std::wcout << L"[HOOK] InternetOpenUrlW: " << (lpszUrl?lpszUrl:L"(null)") << std::endl;
    return fpInternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}
BOOL WINAPI Hooked_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength) {
    std::cout << "[HOOK] HttpSendRequestA" << std::endl;
    return fpHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}
BOOL WINAPI Hooked_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength) {
    std::wcout << L"[HOOK] HttpSendRequestW" << std::endl;
    return fpHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}
BOOL WINAPI Hooked_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    std::cout << "[HOOK] InternetReadFile" << std::endl;
    return fpInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}
BOOL WINAPI Hooked_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    std::wcout << L"[HOOK] WinHttpSendRequest" << std::endl;
    return fpWinHttpSendRequest(hRequest, pwszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}
BOOL WINAPI Hooked_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwBytesToRead, LPDWORD lpdwBytesRead) {
    std::cout << "[HOOK] WinHttpReadData" << std::endl;
    return fpWinHttpReadData(hRequest, lpBuffer, dwBytesToRead, lpdwBytesRead);
}

// Сравнение ключа
int __cdecl Hooked_Strcmp(const char* s1, const char* s2) {
    std::cout << "[HOOK] strcmp: " << (s1?s1:"(null)") << " vs " << (s2?s2:"(null)") << std::endl;
    return fpStrcmp(s1, s2);
}
int __cdecl Hooked_Memcmp(const void* s1, const void* s2, size_t len) {
    std::cout << "[HOOK] memcmp" << std::endl;
    return fpMemcmp(s1, s2, len);
}

// UI
UINT WINAPI Hooked_GetDlgItemTextA(HWND hDlg, int nIDDlgItem, LPSTR lpString, int nMaxCount) {
    UINT result = fpGetDlgItemTextA(hDlg, nIDDlgItem, lpString, nMaxCount);
    std::cout << "[HOOK] GetDlgItemTextA: " << lpString << std::endl;
    return result;
}
UINT WINAPI Hooked_GetDlgItemTextW(HWND hDlg, int nIDDlgItem, LPWSTR lpString, int nMaxCount) {
    UINT result = fpGetDlgItemTextW(hDlg, nIDDlgItem, lpString, nMaxCount);
    std::wcout << L"[HOOK] GetDlgItemTextW: " << lpString << std::endl;
    return result;
}
BOOL WINAPI Hooked_SetWindowTextA(HWND hWnd, LPCSTR lpString) {
    std::cout << "[HOOK] SetWindowTextA: " << (lpString?lpString:"(null)") << std::endl;
    return fpSetWindowTextA(hWnd, lpString);
}
BOOL WINAPI Hooked_SetWindowTextW(HWND hWnd, LPCWSTR lpString) {
    std::wcout << L"[HOOK] SetWindowTextW: " << (lpString?lpString:L"(null)") << std::endl;
    return fpSetWindowTextW(hWnd, lpString);
}

// Файлы
BOOL WINAPI Hooked_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::cout << "[HOOK] WriteFile, " << nNumberOfBytesToWrite << " bytes" << std::endl;
    return fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
BOOL WINAPI Hooked_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    std::cout << "[HOOK] ReadFile, " << nNumberOfBytesToRead << " bytes" << std::endl;
    return fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

// Крипто/WinAPI (auth/crypto/credentials)
BOOL WINAPI Hooked_LogonUserA(LPCSTR user, LPCSTR domain, LPCSTR pass, DWORD logonType, DWORD logonProvider, PHANDLE phToken) {
    std::cout << "[HOOK] LogonUserA: " << user << std::endl;
    return fpLogonUserA(user, domain, pass, logonType, logonProvider, phToken);
}
BOOL WINAPI Hooked_LogonUserW(LPCWSTR user, LPCWSTR domain, LPCWSTR pass, DWORD logonType, DWORD logonProvider, PHANDLE phToken) {
    std::wcout << L"[HOOK] LogonUserW: " << (user ? user : L"(null)") << std::endl;
    return fpLogonUserW(user, domain, pass, logonType, logonProvider, phToken);
}
BOOL WINAPI Hooked_CredWriteA(PCREDENTIALA cred, DWORD flags) {
    std::cout << "[HOOK] CredWriteA" << std::endl;
    return fpCredWriteA(cred, flags);
}
BOOL WINAPI Hooked_CredWriteW(PCREDENTIALW cred, DWORD flags) {
    std::wcout << L"[HOOK] CredWriteW" << std::endl;
    return fpCredWriteW(cred, flags);
}
BOOL WINAPI Hooked_CryptAcquireContextA(HCRYPTPROV_PTR phProv, LPCSTR pszContainer, LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
    std::cout << "[HOOK] CryptAcquireContextA" << std::endl;
    return fpCryptAcquireContextA(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}
BOOL WINAPI Hooked_CryptAcquireContextW(HCRYPTPROV_PTR phProv, LPCWSTR pszContainer, LPCWSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
    std::wcout << L"[HOOK] CryptAcquireContextW" << std::endl;
    return fpCryptAcquireContextW(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}
BOOL WINAPI Hooked_CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags) {
    std::cout << "[HOOK] CryptReleaseContext" << std::endl;
    return fpCryptReleaseContext(hProv, dwFlags);
}
BOOL WINAPI Hooked_CryptDecrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL bFinal, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
    std::cout << "[HOOK] CryptDecrypt" << std::endl;
    return fpCryptDecrypt(key, hash, bFinal, dwFlags, pbData, pdwDataLen);
}
BOOL WINAPI Hooked_CryptEncrypt(HCRYPTKEY key, HCRYPTHASH hash, BOOL bFinal, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen) {
    std::cout << "[HOOK] CryptEncrypt" << std::endl;
    return fpCryptEncrypt(key, hash, bFinal, dwFlags, pbData, pdwDataLen, dwBufLen);
}
BOOL WINAPI Hooked_CryptVerifySignature(HCRYPTHASH hash, const BYTE* pbSignature, DWORD cbSignature, HCRYPTKEY hPubKey, LPCSTR sDescription, DWORD dwFlags) {
    std::cout << "[HOOK] CryptVerifySignature" << std::endl;
    return fpCryptVerifySignature(hash, pbSignature, cbSignature, hPubKey, sDescription, dwFlags);
}
SECURITY_STATUS WINAPI Hooked_AcquireCredentialsHandleA(
    LPSTR pszPrincipal, LPSTR pszPackage, ULONG fCredentialUse, PLUID pvLogonId, PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn, PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry) {
    std::cout << "[HOOK] AcquireCredentialsHandleA" << std::endl;
    return fpAcquireCredentialsHandleA(pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_AcquireCredentialsHandleW(
    LPWSTR pszPrincipal, LPWSTR pszPackage, ULONG fCredentialUse, PLUID pvLogonId, PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn, PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry) {
    std::wcout << L"[HOOK] AcquireCredentialsHandleW" << std::endl;
    return fpAcquireCredentialsHandleW(pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData, pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput,
     ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry) {
    std::cout << "[HOOK] AcceptSecurityContext" << std::endl;
    return fpAcceptSecurityContext(phCredential, phContext, pInput, fContextReq, TargetDataRep, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_InitializeSecurityContextA(PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR* pszTargetName,
     ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput,
     ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry) {
    std::cout << "[HOOK] InitializeSecurityContextA" << std::endl;
    return fpInitializeSecurityContextA(phCredential, phContext, pszTargetName, fContextReq, Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR* pszTargetName,
     ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput,
     ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry) {
    std::wcout << L"[HOOK] InitializeSecurityContextW" << std::endl;
    return fpInitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}
SECURITY_STATUS WINAPI Hooked_ImpersonateSecurityContext(PCtxtHandle phContext) {
    std::cout << "[HOOK] ImpersonateSecurityContext" << std::endl;
    return fpImpersonateSecurityContext(phContext);
}
SECURITY_STATUS WINAPI Hooked_RevertSecurityContext(PCtxtHandle phContext) {
    std::cout << "[HOOK] RevertSecurityContext" << std::endl;
    return fpRevertSecurityContext(phContext);
}
BOOL WINAPI Hooked_AuthzInitializeResourceManager(DWORD flags, PFN_AUTHZ_DYNAMIC_ACCESS_CHECK fn1, PFN_AUTHZ_COMPUTE_DYNAMIC_GROUPS fn2, PFN_AUTHZ_FREE_DYNAMIC_GROUPS fn3, PCWSTR sz, PAUTHZ_RESOURCE_MANAGER_HANDLE handle) {
    std::wcout << L"[HOOK] AuthzInitializeResourceManager" << std::endl;
    return fpAuthzInitializeResourceManager(flags, fn1, fn2, fn3, sz, handle);
}
BOOL WINAPI Hooked_AuthzAccessCheck(DWORD flags, AUTHZ_CLIENT_CONTEXT_HANDLE ctx, PAUTHZ_ACCESS_REQUEST req, AUTHZ_AUDIT_EVENT_HANDLE audit, PSECURITY_DESCRIPTOR sd, PSECURITY_DESCRIPTOR* pSidArray, DWORD count, PAUTHZ_ACCESS_REPLY reply, PAUTHZ_ACCESS_CHECK_RESULTS_HANDLE result) {
    std::cout << "[HOOK] AuthzAccessCheck" << std::endl;
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
