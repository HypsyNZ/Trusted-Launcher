#pragma once

#include <WtsApi32.h>
#pragma comment(lib, "WtsApi32.lib")

#include <Userenv.h>
#pragma comment(lib, "Userenv.lib")

ULONGLONG WINAPI GetPerfTickCount()
{
    LARGE_INTEGER Frequency, PerformanceCount;

    if (QueryPerformanceFrequency(&Frequency))
    {
        if (QueryPerformanceCounter(&PerformanceCount))
        {
            return (PerformanceCount.QuadPart * 1000 / Frequency.QuadPart);
        }
    }

    return GetTickCount64();
}

BOOL WINAPI AdjustTokenPrivilegesSimple(
    _In_ HANDLE TokenHandle,
    _In_ PLUID_AND_ATTRIBUTES Privileges,
    _In_ DWORD PrivilegeCount)
{
    BOOL hr = FALSE;

    if (Privileges && PrivilegeCount)
    {
        DWORD PSize = sizeof(LUID_AND_ATTRIBUTES) * PrivilegeCount;
        DWORD TPSize = PSize + sizeof(DWORD);

        PTOKEN_PRIVILEGES pTP = nullptr;

        LPVOID* tes = reinterpret_cast<LPVOID*>(&pTP);

        *tes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TPSize);

        if (*tes)
        {
            pTP->PrivilegeCount = PrivilegeCount;
            memcpy(pTP->Privileges, Privileges, PSize);

            hr = AdjustTokenPrivileges(TokenHandle, FALSE, pTP, TPSize, nullptr, nullptr);

            HeapFree(GetProcessHeap(), 0, pTP);
        }
    }

    return hr;
}

BOOL WINAPI AdjustTokenAllPrivileges(
    _In_ HANDLE TokenHandle,
    _In_ DWORD Attributes)
{
    HRESULT hr = FALSE;
    DWORD Length = 0;

    if (!GetTokenInformation(
        TokenHandle,
        TokenPrivileges,
        nullptr,
        0,
        &Length))
    {
        PVOID* pv = reinterpret_cast<PVOID*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length));
        if (pv)
        {
            if (!GetTokenInformation(TokenHandle, TokenPrivileges, pv, Length, &Length))
            {
                HeapFree(GetProcessHeap(), 0, pv);
                pv = nullptr;
            }
            else
            {
                PTOKEN_PRIVILEGES pTokenPrivileges = reinterpret_cast<PTOKEN_PRIVILEGES>(pv);

                for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i)
                {
                    pTokenPrivileges->Privileges[i].Attributes = Attributes;
                }

                hr = AdjustTokenPrivilegesSimple(
                    TokenHandle,
                    pTokenPrivileges->Privileges,
                    pTokenPrivileges->PrivilegeCount);

                HeapFree(GetProcessHeap(), 0, pTokenPrivileges);
            }
        }
    }

    return hr;
}

HRESULT WINAPI StartServiceSimple(
    _In_ LPCWSTR ServiceName,
    _Out_ LPSERVICE_STATUS_PROCESS ServiceStatus)
{
    HRESULT hr = E_INVALIDARG;

    if (ServiceStatus && ServiceName)
    {
        hr = S_OK;

        memset(ServiceStatus, 0, sizeof(LPSERVICE_STATUS_PROCESS));

        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (hSCM)
        {
            SC_HANDLE hService = OpenServiceW(
                hSCM,
                ServiceName,
                SERVICE_QUERY_STATUS | SERVICE_START);
            if (hService)
            {
                DWORD nBytesNeeded = 0;
                DWORD nOldCheckPoint = 0;
                ULONGLONG nLastTick = 0;
                bool bStartServiceWCalled = false;

                while (QueryServiceStatusEx(
                    hService,
                    SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<LPBYTE>(ServiceStatus),
                    sizeof(SERVICE_STATUS_PROCESS),
                    &nBytesNeeded))
                {
                    if (SERVICE_STOPPED == ServiceStatus->dwCurrentState)
                    {
                        // Failed if the service had stopped again.
                        if (bStartServiceWCalled)
                        {
                            hr = S_FALSE;
                            break;
                        }

                        if (!StartServiceW(hService, 0, nullptr))
                        {
                            break;
                        }

                        hr = S_OK;
                        bStartServiceWCalled = true;
                    }
                    else if (
                        SERVICE_STOP_PENDING
                        == ServiceStatus->dwCurrentState ||
                        SERVICE_START_PENDING
                        == ServiceStatus->dwCurrentState)
                    {
                        ULONGLONG nCurrentTick = GetPerfTickCount();

                        if (!nLastTick)
                        {
                            nLastTick = nCurrentTick;
                            nOldCheckPoint = ServiceStatus->dwCheckPoint;

                            SleepEx(250, FALSE);
                        }
                        else
                        {
                            if (ServiceStatus->dwCheckPoint
                                <= nOldCheckPoint)
                            {
                                ULONGLONG nDiff = nCurrentTick - nLastTick;
                                if (nDiff > ServiceStatus->dwWaitHint)
                                {
                                    hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                                    break;
                                }
                            }

                            // Continue looping.
                            nLastTick = 0;
                        }
                    }
                    else
                    {
                        break;
                    }
                }

                CloseServiceHandle(hService);
            }

            CloseServiceHandle(hSCM);
        }
    }

    return hr;
}

BOOL WINAPI GetLsassProcessId(
    _Out_ PDWORD ProcessId)
{
    BOOL r = FALSE;

    if (ProcessId)
    {
        *ProcessId = static_cast<DWORD>(-1);

        PWTS_PROCESS_INFOW pProcesses = nullptr;
        DWORD dwProcessCount = 0;

        if (WTSEnumerateProcessesW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &pProcesses,
            &dwProcessCount))
        {
            for (DWORD i = 0; i < dwProcessCount; ++i)
            {
                PWTS_PROCESS_INFOW pProcess = &pProcesses[i];

                if (pProcess->SessionId != 0)
                    continue;

                if (!pProcess->pProcessName)
                    continue;

                if (_wcsicmp(L"lsass.exe", pProcess->pProcessName) != 0)
                    continue;

                if (!pProcess->pUserSid)
                    continue;

                if (!IsWellKnownSid(pProcess->pUserSid, WELL_KNOWN_SID_TYPE::WinLocalSystemSid))
                    continue;

                *ProcessId = pProcess->ProcessId;

                r = TRUE;
                break;
            }

            WTSFreeMemory(pProcesses);
        }
    }

    return r;
}

HRESULT WINAPI OpenLsassProcess(
    _In_ DWORD DesiredAccess,
    _In_ BOOL InheritHandle,
    _Out_ PHANDLE ProcessHandle)
{
    DWORD dwLsassPID = static_cast<DWORD>(-1);

    if (GetLsassProcessId(&dwLsassPID))
    {
        *ProcessHandle = OpenProcess(DesiredAccess, InheritHandle, dwLsassPID);
        if (ProcessHandle)
        {
            return S_OK;
        }
    }

    return S_FALSE;
}

HRESULT WINAPI OpenServiceProcessToken(
    _In_ LPCWSTR ServiceName,
    _In_ DWORD DesiredAccess,
    _Out_ PHANDLE TokenHandle)
{
    HANDLE ProcessHandle = INVALID_HANDLE_VALUE;
    SERVICE_STATUS_PROCESS ServiceStatus;

    HRESULT hr = StartServiceSimple(ServiceName, &ServiceStatus);
    if (hr == S_OK)
    {
        ProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, ServiceStatus.dwProcessId);
    }

    if (ProcessHandle)
    {
        hr = OpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle) ? S_OK : S_FALSE;
        CloseHandle(ProcessHandle);
    }

    return hr;
}

BOOL WINAPI ExpandEnvironmentStringsEx(
    _In_ LPCWSTR lpSrc,
    _Out_opt_ LPWSTR lpDst,
    _In_ DWORD nSize,
    _Out_ PDWORD pReturnLength)
{
    if (pReturnLength)
    {
        *pReturnLength = ExpandEnvironmentStringsW(lpSrc, lpDst, nSize);
        if (*pReturnLength)
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL WINAPI ExpandEnvironmentStringsWithMemory(
    _In_ LPCWSTR Source,
    _Out_ LPWSTR* Destination)
{
    DWORD AllocatedLength = 0;
    DWORD ActualLength = 0;

    BOOL hr = FALSE;

    if (Destination)
    {
        hr = ExpandEnvironmentStringsEx(Source, nullptr, 0, &AllocatedLength);
        if (hr)
        {

            PVOID* pv = reinterpret_cast<PVOID*>(Destination);
            *pv = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AllocatedLength * sizeof(wchar_t));

            if (*pv)
            {
                hr = ExpandEnvironmentStringsEx(Source, *Destination, AllocatedLength, &ActualLength);
                if (hr)
                {
                    if (AllocatedLength != ActualLength)
                    {
                        hr = FALSE;
                    }
                }
            }
        }

        if (!hr)
        {
            HeapFree(GetProcessHeap(), 0, *Destination);
            *Destination = nullptr;
        }
    }

    return hr;
}

