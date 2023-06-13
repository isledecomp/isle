/*
 * Copyright (c) 2023 Huang Qinjin
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <windows.h>
#include <shlwapi.h>

//#pragma comment(lib, "shell32.lib")
//#pragma comment(lib, "shlwapi.lib")
//#pragma comment(linker, "/ENTRY:wWinMainCRTStartup")
//#pragma comment(linker, "/SUBSYSTEM:CONSOLE")


static HANDLE hStdIn  = INVALID_HANDLE_VALUE;
static HANDLE hStdOut = INVALID_HANDLE_VALUE;
static HANDLE hStdErr = INVALID_HANDLE_VALUE;

static DWORD run(LPWSTR lpCmdLine)
{
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdIn;
    si.hStdOutput = hStdOut;
    si.hStdError = hStdErr;

    PROCESS_INFORMATION pi = {};

    DWORD dwExitCode;
    if (CreateProcessW(nullptr, lpCmdLine, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi))
    {
        WaitForSingleObject(pi.hProcess, INFINITE);

        if (!GetExitCodeProcess(pi.hProcess, &dwExitCode))
        {
            dwExitCode = GetLastError();
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        dwExitCode = GetLastError();
    }

    return dwExitCode;
}

static DWORD mt(LPWSTR lpCmdLine)
{
    DWORD dwExitCode = run(lpCmdLine);
    // https://gitlab.kitware.com/cmake/cmake/-/blob/v3.26.0/Source/cmcmd.cxx#L2405
    if (dwExitCode == 0x41020001)
        dwExitCode = 0xbb;
    return dwExitCode;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    (void) hInstance;
    (void) hPrevInstance;
    (void) nCmdShow;

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(lpCmdLine, &argc);
    if (argc <= 0) return 0;

    wchar_t buf[32768];
    if (GetEnvironmentVariableW(L"WINE_MSVC_STDIN", buf, ARRAYSIZE(buf)))
    {
        SECURITY_ATTRIBUTES attr = {};
        attr.nLength = sizeof(attr);
        attr.bInheritHandle = TRUE;

        hStdIn = CreateFileW(buf, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (GetEnvironmentVariableW(L"WINE_MSVC_STDOUT", buf, ARRAYSIZE(buf)))
    {
        SECURITY_ATTRIBUTES attr = {};
        attr.nLength = sizeof(attr);
        attr.bInheritHandle = TRUE;

        hStdOut = CreateFileW(buf, GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (GetEnvironmentVariableW(L"WINE_MSVC_STDERR", buf, ARRAYSIZE(buf)))
    {
        SECURITY_ATTRIBUTES attr = {};
        attr.nLength = sizeof(attr);
        attr.bInheritHandle = TRUE;

        hStdErr = CreateFileW(buf, GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (hStdIn == INVALID_HANDLE_VALUE)
    {
        hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    }
    if (hStdOut == INVALID_HANDLE_VALUE)
    {
        hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    if (hStdErr == INVALID_HANDLE_VALUE)
    {
        hStdErr = GetStdHandle(STD_ERROR_HANDLE);
    }

    LPCWSTR const exe = PathFindFileNameW(argv[0]);

    if (PathMatchSpecW(exe, L"mt.exe"))
        return mt(lpCmdLine);

    return run(lpCmdLine);
}
