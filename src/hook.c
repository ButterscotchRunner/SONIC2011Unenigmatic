#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <wctype.h>

static wchar_t outDir[MAX_PATH];
static wchar_t outFile[MAX_PATH];
static wchar_t logFile[MAX_PATH];

static void initPaths() {
    wchar_t base[MAX_PATH];
    GetModuleFileNameW(nullptr, base, MAX_PATH);
    wchar_t* slash = wcsrchr(base, L'\\');
    if (slash)
        *slash = 0;

    wcscpy(outDir, base);
    wcscat(outDir,  L"\\dump");

    wcscpy(outFile, base);
    wcscat(outFile, L"\\dump\\datawin.dump");

    wcscpy(logFile, base);
    wcscat(logFile, L"\\dump\\hook.log");

    CreateDirectoryW(outDir, nullptr);
}

// Tiny inline-hook engine (unhook / call / rehook).
typedef struct {
    void* target;
    unsigned char orig[14];
    unsigned char jmp[14];
    CRITICAL_SECTION cs;
    int on;
} Hook;

static void hookInstall(Hook* hook, void* target, void* detour) {
    DWORD old;
    hook->target = target;
    memcpy(hook->orig, target, 14);
    // jmp qword ptr [rip+0]; <8-byte absolute addr>
    hook->jmp[0] = 0xFF; hook->jmp[1] = 0x25; *(DWORD*) (hook->jmp + 2) = 0;
    *(void**) (hook->jmp + 6) = detour;
    InitializeCriticalSection(&hook->cs);
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, hook->jmp, 14);
    hook->on = 1;
}

static void hookOff(Hook* hook) { EnterCriticalSection(&hook->cs); memcpy(hook->target, hook->orig, 14); }
static void hookOn(Hook* hook) { memcpy(hook->target, hook->jmp,  14); LeaveCriticalSection(&hook->cs); }

// State
static Hook hookCreateW, hookCreateA, hookRead, hookWrite;
static HANDLE trackedHandles[256];
static int trackedCount;
static HANDLE outputHandle = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION stateLock;

static void logMsg(const char* fmt, ...) {
    char buf[512]; va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
    HANDLE f = CreateFileW(logFile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, 0, nullptr);
    if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, buf, n, &w, nullptr); CloseHandle(f); }
}

static int wstrHasDataWin(const wchar_t* s) {
    if (!s)
        return 0;

    for (const wchar_t* p = s; *p; p++) {
        const wchar_t* a = p;
        const wchar_t* b = L"data.win";

        while (*b && *a && towlower(*a) == *b) {
            a++;
            b++;
        }

        if (!*b) return 1;
    }

    return 0;
}
static int astrHasDataWin(const char* s) {
    if (!s)
        return 0;

    for (const char* p = s; *p; p++) {
        const char* a = p;
        const char* b = "data.win";

        while (*b && *a && tolower((unsigned char) *a) == *b) {
            a++;
            b++;
        }

        if (!*b)
            return 1;
    }
    return 0;
}

static void track(HANDLE handle) {
    EnterCriticalSection(&stateLock);
    if (256 > trackedCount)
        trackedHandles[trackedCount++] = handle;
    LeaveCriticalSection(&stateLock);
}

static int tracked(HANDLE handle) {
    int r = 0;
    EnterCriticalSection(&stateLock);
    for (int i = 0; trackedCount > i; i++) {
        if (trackedHandles[i] == handle) {
            r = 1;
            break;
        }
    }
    LeaveCriticalSection(&stateLock);
    return r;
}

static void dumpAt(LONGLONG offset, const void* buf, DWORD n) {
    EnterCriticalSection(&stateLock);
    // Disable the hook so we don't end up listening to our own writes
    hookOff(&hookCreateW);
    if (outputHandle == INVALID_HANDLE_VALUE) {
        outputHandle = CreateFileW(outFile, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    }
    hookOn(&hookCreateW);
    if (outputHandle != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER li; li.QuadPart = offset;
        SetFilePointerEx(outputHandle, li, nullptr, FILE_BEGIN);
        hookOff(&hookWrite);
        DWORD w; WriteFile(outputHandle, buf, n, &w, nullptr);
        hookOn(&hookWrite);
    }
    LeaveCriticalSection(&stateLock);
}

// Detours
typedef HANDLE (WINAPI* CreateFileWFn)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* CreateFileAFn)(LPCSTR , DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI* ReadFileFn)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI* WriteFileFn)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

static HANDLE WINAPI myCreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE templ) {
    hookOff(&hookCreateW);
    HANDLE r = ((CreateFileWFn) hookCreateW.target)(name, access, share, sa, disp, flags, templ);
    hookOn(&hookCreateW);
    if (r != INVALID_HANDLE_VALUE && wstrHasDataWin(name)) {
        logMsg("CreateFileW data.win -> handle %p (%ws)\n", r, name);
        track(r);
    }
    return r;
}

static HANDLE WINAPI myCreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE templ) {
    hookOff(&hookCreateA);
    HANDLE r = ((CreateFileAFn) hookCreateA.target)(name, access, share, sa, disp, flags, templ);
    hookOn(&hookCreateA);
    if (r != INVALID_HANDLE_VALUE && astrHasDataWin(name)) {
        logMsg("CreateFileA data.win -> handle %p (%s)\n", r, name);
        track(r);
    }
    return r;
}

static BOOL WINAPI myReadFile(HANDLE handle, LPVOID buf, DWORD n, LPDWORD got, LPOVERLAPPED ov) {
    LONGLONG offset = 0; int t = tracked(handle);
    if (t) {
        if (ov) offset = ((LONGLONG) ov->OffsetHigh << 32) | ov->Offset;
        else { LARGE_INTEGER z = {0}, cur; SetFilePointerEx(handle, z, &cur, FILE_CURRENT); offset = cur.QuadPart; }
    }
    hookOff(&hookRead);
    BOOL r = ((ReadFileFn) hookRead.target)(handle, buf, n, got, ov);
    hookOn(&hookRead);
    if (t && r && got && *got) { dumpAt(offset, buf, *got); logMsg("ReadFile @%lld len %u\n", offset, *got); }
    return r;
}

static BOOL WINAPI myWriteFile(HANDLE handle, LPCVOID buf, DWORD n, LPDWORD put, LPOVERLAPPED ov) {
    LONGLONG offset = 0;
    int t = tracked(handle);
    if (t) {
        if (ov) {
            offset = ((LONGLONG) ov->OffsetHigh << 32) | ov->Offset;
        }
        else {
            LARGE_INTEGER z = {0}, cur;
            SetFilePointerEx(handle, z, &cur, FILE_CURRENT);
            offset = cur.QuadPart;
        }
    }
    hookOff(&hookWrite);
    BOOL r = ((WriteFileFn) hookWrite.target)(handle, buf, n, put, ov);
    hookOn(&hookWrite);
    if (t && r && put && *put) {
        dumpAt(offset, buf, *put);
        logMsg("WriteFile @%lld len %u\n", offset, *put);
    }
    return r;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID res) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        initPaths();
        InitializeCriticalSection(&stateLock);
        HMODULE k = GetModuleHandleW(L"kernel32.dll");
        hookInstall(&hookCreateW, GetProcAddress(k, "CreateFileW"), myCreateFileW);
        hookInstall(&hookCreateA, GetProcAddress(k, "CreateFileA"), myCreateFileA);
        hookInstall(&hookRead, GetProcAddress(k, "ReadFile"), myReadFile);
        hookInstall(&hookWrite, GetProcAddress(k, "WriteFile"), myWriteFile);
        logMsg("Hook installed\n");
    }
    return TRUE;
}
