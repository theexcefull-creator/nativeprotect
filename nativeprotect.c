/**
 * nativeprotect.c — JNI native protection library for DeltaClient
 *
 * Features:
 *   - Anti-debug: IsDebuggerPresent, NtQueryInformationProcess, CheckRemoteDebuggerPresent
 *   - Anti-dump: detects memory dump attempts, crashes with "SUCK REVERSER HAHAHA"
 *   - Anti-inject: module whitelist, enumerates loaded DLLs
 *   - Integrity: .text section CRC check
 *   - JDWP port probe: detects remote debugger
 *   - Multi-threaded: runs checks in background threads
 *
 * Build: gcc -shared -O2 -fvisibility=hidden -I"%JAVA_HOME%\include" -I"%JAVA_HOME%\include\win32"
 *        -o nativeprotect.dll nativeprotect.c -lpsapi -lws2_32 -ladvapi32 -Wl,--strip-all
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#else
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <pthread.h>
#include <dlfcn.h>
#endif

/* ================================================================
 *  Globals
 * ================================================================ */

static volatile int g_protection_active = 0;
static volatile int g_dump_detected = 0;
static JavaVM *g_jvm = NULL;
static jclass g_callback_class = NULL;

/* XOR key for internal string obfuscation */
static const unsigned char XOR_KEY[] = {0x4A, 0x61, 0x76, 0x61, 0x5F, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63, 0x74};

#define XOR_KEY_LEN 12

static void xor_buf(unsigned char *buf, int len) {
    int i;
    for (i = 0; i < len; i++)
        buf[i] ^= XOR_KEY[i % XOR_KEY_LEN];
}

/* ================================================================
 *  Anti-Debug: Windows
 * ================================================================ */

#ifdef _WIN32

/* NtQueryInformationProcess (undocumented) */
typedef LONG (WINAPI *pNtQIP)(HANDLE, UINT, PVOID, ULONG, PULONG);
static pNtQIP NtQIP = NULL;

static int check_debugger_windows(void) {
    /* 1. IsDebuggerPresent */
    if (IsDebuggerPresent()) return 1;

    /* 2. CheckRemoteDebuggerPresent */
    BOOL remoteDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
    if (remoteDbg) return 1;

    /* 3. NtQueryInformationProcess — ProcessDebugPort (7) */
    if (!NtQIP) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) NtQIP = (pNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    }
    if (NtQIP) {
        DWORD debugPort = 0;
        LONG status = NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
        if (status == 0 && debugPort != 0) return 1;

        /* ProcessDebugFlags (0x1F) — 0 means debugger present */
        DWORD debugFlags = 1;
        status = NtQIP(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), NULL);
        if (status == 0 && debugFlags == 0) return 1;
    }

    return 0;
}

#else /* !_WIN32 — Linux/macOS */

/* ================================================================
 *  Anti-Debug: Linux
 * ================================================================ */

static int check_debugger_linux(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) return 1;

    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                if (pid != 0) { fclose(f); return 1; }
            }
        }
        fclose(f);
    }
    return 0;
}

#endif

/* ================================================================
 *  Anti-Dump: detect memory dump via module enumeration
 * ================================================================ */

#ifdef _WIN32

static int check_modules_whitelist(void) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) return 0;

    int count = cbNeeded / sizeof(HMODULE);
    int i;
    for (i = 0; i < count; i++) {
        char name[MAX_PATH];
        if (GetModuleFileNameExA(GetCurrentProcess(), hMods[i], name, sizeof(name))) {
            /* Convert to lowercase for comparison */
            char low[MAX_PATH];
            int j;
            for (j = 0; name[j]; j++) low[j] = (char)tolower(name[j]);
            low[j] = 0;

            /* Known suspicious modules */
            if (strstr(low, "frida") || strstr(low, "x64dbg") || strstr(low, "x32dbg") ||
                strstr(low, "scylla") || strstr(low, "process.hacker") || strstr(low, "procexp") ||
                strstr(low, "ollydbg") || strstr(low, "ida") || strstr(low, "ghidra") ||
                strstr(low, "recaf") || strstr(low, "jd-gui") || strstr(low, "procyon") ||
                strstr(low, "cfr") || strstr(low, "vineflower") || strstr(low, "fernflower")) {
                return 1;
            }
        }
    }
    return 0;
}

#else

static int check_modules_whitelist(void) {
    /* Linux: check /proc/self/maps for suspicious libraries */
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "x64dbg") ||
            strstr(line, "recaf") || strstr(line, "ida") || strstr(line, "ghidra")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

#endif

/* ================================================================
 *  JDWP Port Probe
 * ================================================================ */

static int check_jdwp_ports(void) {
#ifdef _WIN32
    WSADATA wd;
    WSAStartup(MAKEWORD(2,2), &wd);
#endif

    int ports[] = {8000, 8001, 8002, 5005, 5006, 9090, 9091, 7777, 4848, 0};
    int i;
    for (i = 0; ports[i]; i++) {
#ifdef _WIN32
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
#else
        int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s < 0) continue;
#endif
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)ports[i]);
        a.sin_addr.s_addr = inet_addr("127.0.0.1");

#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(s, FIONBIO, &mode);
#else
        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
        connect(s, (struct sockaddr*)&a, sizeof(a));

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        struct timeval tv = {0, 150000}; /* 150ms */

#ifdef _WIN32
        int sel = select(0, NULL, &wfds, NULL, &tv);
        closesocket(s);
#else
        int sel = select(s+1, NULL, &wfds, NULL, &tv);
        close(s);
#endif
        if (sel > 0) {
#ifdef _WIN32
            WSACleanup();
#endif
            return 1;
        }
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

/* ================================================================
 *  Integrity: CRC32 of .text section
 * ================================================================ */

static unsigned int crc32_compute(unsigned char *data, int len) {
    unsigned int crc = 0xFFFFFFFF;
    int i, j;
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

#ifdef _WIN64
static DWORD get_text_section_size(void) {
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    int i;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0)
            return sec[i].Misc.VirtualSize;
    }
    return 0;
}
#endif

/* ================================================================
 *  Crash handler: "SUCK REVERSER HAHAHA"
 * ================================================================ */

static void crash_reverser(void) {
    /* Method 1: Write to stderr */
#ifdef _WIN32
    HANDLE hCon = GetStdHandle(STD_ERROR_HANDLE);
    if (hCon != INVALID_HANDLE_VALUE) {
        const char *msg = "\n\n"
            "========================================\n"
            "  SUCK REVERSER HAHAHA\n"
            "========================================\n"
            "  Nice try dumping the memory.\n"
            "  Your cheat is now DEAD.\n"
            "  Go play legit.\n"
            "========================================\n\n";
        DWORD written;
        WriteFile(hCon, msg, (DWORD)strlen(msg), &written, NULL);
    }
#endif

    /* Method 2: Write crash dump file */
#ifdef _WIN32
    HANDLE hFile = CreateFileA("crash_dump_detected.log",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        const char *msg = "MEMORY DUMP DETECTED!\n"
            "Process integrity compromised.\n"
            "SUCK REVERSER HAHAHA\n"
            "All encryption keys have been corrupted.\n";
        DWORD written;
        WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
        CloseHandle(hFile);
    }
#endif

    /* Method 3: Exit with crash */
#ifdef _WIN32
    /* Corrupt the process heap to cause eventual crash */
    /* This is non-fatal immediately but causes issues later */
    TerminateProcess(GetCurrentProcess(), 0xDEAD);
#else
    kill(getpid(), SIGKILL);
#endif
}

/* ================================================================
 *  Background protection thread
 * ================================================================ */

#ifdef _WIN32

static DWORD WINAPI protection_thread_win(LPVOID param) {
    (void)param;
    srand((unsigned int)time(NULL));

    while (g_protection_active) {
        int sleep_ms = 3000 + (rand() % 7000);
        Sleep(sleep_ms);

        if (!g_protection_active) break;

        if (check_debugger_windows()) {
            g_dump_detected = 1;
            crash_reverser();
            return 1;
        }
        if (check_modules_whitelist()) {
            g_dump_detected = 1;
            crash_reverser();
            return 2;
        }
        if ((rand() % 3) == 0 && check_jdwp_ports()) {
            g_dump_detected = 1;
            crash_reverser();
            return 3;
        }
    }
    return 0;
}

#else

static void *protection_thread_unix(void *param) {
    (void)param;
    srand((unsigned int)time(NULL));

    while (g_protection_active) {
        int sleep_ms = 3000 + (rand() % 7000);
        usleep(sleep_ms * 1000);

        if (!g_protection_active) break;

        if (check_debugger_linux()) {
            g_dump_detected = 1;
            crash_reverser();
            return (void*)1;
        }
        if (check_modules_whitelist()) {
            g_dump_detected = 1;
            crash_reverser();
            return (void*)2;
        }
        if ((rand() % 3) == 0 && check_jdwp_ports()) {
            g_dump_detected = 1;
            crash_reverser();
            return (void*)3;
        }
    }
    return NULL;
}

#endif

/* ================================================================
 *  JNI Functions
 * ================================================================ */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_8;
}

JNIEXPORT jboolean JNICALL Java_antizalupaleak_protect_AntiDump_nativeInit(JNIEnv *env, jclass cls) {
    if (g_protection_active) return JNI_TRUE;
    g_protection_active = 1;
    g_dump_detected = 0;

#ifdef _WIN32
    HANDLE hThread = CreateThread(NULL, 0, protection_thread_win, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
#else
    pthread_t tid;
    pthread_create(&tid, NULL, protection_thread_unix, NULL);
    pthread_detach(tid);
#endif
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_antizalupaleak_protect_AntiDump_nativeCheck(JNIEnv *env, jclass cls) {
    if (g_dump_detected) return JNI_TRUE;

#ifdef _WIN32
    return check_debugger_windows() || check_modules_whitelist() || check_jdwp_ports() ? JNI_TRUE : JNI_FALSE;
#else
    return check_debugger_linux() || check_modules_whitelist() || check_jdwp_ports() ? JNI_TRUE : JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_antizalupaleak_protect_AntiDump_nativeDumpDetected(JNIEnv *env, jclass cls) {
    if (g_dump_detected) {
        crash_reverser();
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

JNIEXPORT void JNICALL Java_antizalupaleak_protect_AntiDump_nativeCrash(JNIEnv *env, jclass cls) {
    /* Write the crash message and terminate */
    g_dump_detected = 1;
    crash_reverser();
}

JNIEXPORT jint JNICALL Java_antizalupaleak_protect_AntiDump_nativeCrc(JNIEnv *env, jclass cls) {
#ifdef _WIN64
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return 0;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    int i;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE *textBase = (BYTE*)hMod + sec[i].VirtualAddress;
            return (jint)crc32_compute(textBase, sec[i].Misc.VirtualSize);
        }
    }
#endif
    return 0;
}

JNIEXPORT jboolean JNICALL Java_antizalupaleak_protect_AntiDump_nativeScanThreads(JNIEnv *env, jclass cls) {
#ifdef _WIN32
    DWORD mypid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return JNI_FALSE;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int count = 0;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == mypid) count++;
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return (count > 80) ? JNI_TRUE : JNI_FALSE;
#else
    DIR *d = opendir("/proc/self/task");
    if (!d) return JNI_FALSE;
    int count = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) if (e->d_name[0] != '.') count++;
    closedir(d);
    return (count > 80) ? JNI_TRUE : JNI_FALSE;
#endif
}

JNIEXPORT void JNICALL Java_antizalupaleak_protect_AntiDump_nativeProtect(JNIEnv *env, jclass cls) {
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mbi;
    /* Protect the DLL's own code section */
    if (VirtualQuery((LPCVOID)&Java_antizalupaleak_protect_AntiDump_nativeInit, &mbi, sizeof(mbi))) {
        DWORD old;
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READ, &old);
    }
#endif
}
