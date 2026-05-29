// Launch sonic.exe suspended, inject hook.dll, resume.
#include <windows.h>
#include <stdio.h>

int main() {
    // Resolve sonic.exe and hook.dll from this injector's own folder.
    wchar_t dir[MAX_PATH];
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash)
        *slash = 0;

    wchar_t exePath[MAX_PATH];
    wcscpy(exePath, dir);
    wcscat(exePath, L"\\sonic.exe");

    wchar_t dllPath[MAX_PATH];
    wcscpy(dllPath, dir);
    wcscat(dllPath, L"\\hook.dll");

    STARTUPINFOW startupInformation = { sizeof startupInformation };
    PROCESS_INFORMATION processInformation = { 0 };
    wchar_t cmd[1024];
    wcscpy(cmd, exePath);
    if (!CreateProcessW(exePath, cmd, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, dir, &startupInformation, &processInformation)) {
        printf("CreateProcess failed %lu\n", GetLastError()); return 1;
    }

    // Inject the hook.dll
    SIZE_T sz = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* rem = VirtualAllocEx(processInformation.hProcess, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(processInformation.hProcess, rem, dllPath, sz, nullptr);
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE load = (LPTHREAD_START_ROUTINE) GetProcAddress(k, "LoadLibraryW");

    HANDLE th = CreateRemoteThread(processInformation.hProcess, nullptr, 0, load, rem, 0, nullptr);
    if (!th) {
        printf("CreateRemoteThread failed %lu\n", GetLastError());
        return 1;
    }
    WaitForSingleObject(th, INFINITE);
    DWORD ok = 0; GetExitCodeThread(th, &ok);
    printf("LoadLibraryW returned module 0x%lx\n", ok);
    CloseHandle(th);

    ResumeThread(processInformation.hThread);
    printf("Resumed sonic.exe (pid %lu)\n", processInformation.dwProcessId);
    return 0;
}
