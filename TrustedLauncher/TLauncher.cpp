#define NOMINMAX

#include <SDKDDKVer.h>
#define _WIN32_WINNT_WIN10_TH2 _WIN32_WINNT_WIN10
#define _WIN32_WINNT_WIN10_RS1 _WIN32_WINNT_WIN10

#include <Windows.h>
#include <string>
#include <vector>

#include "Headers\WindowsApi32.h"
#include "Headers\TLauncher.h"

#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4505)
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

std::wstring GetCurrentProcessModulePath()
{
    std::wstring result(MAX_PATH, L'\0');
    GetModuleFileNameW(nullptr, &result[0], (DWORD)(result.capacity()));
    result.resize(wcslen(result.c_str()));
    return result;
}

class SudoResourceManagement
{
private:
    bool m_IsInitialized = false;

    std::wstring m_ExePath;
    std::wstring m_AppPath;

public:
    const std::wstring& ExePath = this->m_ExePath;
    const std::wstring& AppPath = this->m_AppPath;

public:
    SudoResourceManagement() = default;

    ~SudoResourceManagement()
    {
        if (this->m_IsInitialized)
        {
            UnInitialize();
        }
    }

    void Initialize()
    {
        if (!this->m_IsInitialized)
        {
            this->m_ExePath = GetCurrentProcessModulePath();

            this->m_AppPath = this->m_ExePath;
            wcsrchr(&this->m_AppPath[0], L'\\')[0] = L'\0';
            this->m_AppPath.resize(wcslen(this->m_AppPath.c_str()));

            this->m_IsInitialized = true;
        }
    }

    void UnInitialize()
    {
        // TODO: Empty
    }
};

SudoResourceManagement g_ResourceManagement;

int TLauncherMain()
{
    g_ResourceManagement.Initialize();

    BOOL r = RunProcess(L"notepad.exe", g_ResourceManagement.AppPath.c_str());

    if (!r)
    {
        return -1;
    }

    return 0;
}

int main()
{
    return TLauncherMain();
}
