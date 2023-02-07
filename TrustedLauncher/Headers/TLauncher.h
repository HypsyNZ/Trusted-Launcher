#include <utility>

BOOL WINAPI RunProcess(
    _In_ LPCWSTR CommandLine,
    _In_opt_ LPCWSTR CurrentDirectory)
{
    DWORD MandatoryLabelRid = SECURITY_MANDATORY_SYSTEM_RID;
    DWORD ProcessPriority = ABOVE_NORMAL_PRIORITY_CLASS;
    DWORD ShowWindowMode = SW_SHOWDEFAULT;

    DWORD SessionID = static_cast<DWORD>(-1);

    HANDLE CurrentProcessToken = INVALID_HANDLE_VALUE;
    HANDLE DuplicatedCurrentProcessToken = INVALID_HANDLE_VALUE;

    HANDLE OriginalLsassProcessToken = INVALID_HANDLE_VALUE;
    HANDLE SystemToken = INVALID_HANDLE_VALUE;

    HANDLE hToken = INVALID_HANDLE_VALUE;
    HANDLE OriginalToken = INVALID_HANDLE_VALUE;

    DWORD ReturnLength = 0;

    if (OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &CurrentProcessToken))
    {
        if (DuplicateTokenEx(CurrentProcessToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenImpersonation, &DuplicatedCurrentProcessToken))
        {
            LUID_AND_ATTRIBUTES RawPrivilege{};

            if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &RawPrivilege.Luid))
            {
                RawPrivilege.Attributes = SE_PRIVILEGE_ENABLED;

                if (AdjustTokenPrivilegesSimple(DuplicatedCurrentProcessToken, &RawPrivilege, 1))
                {
                    if (SetThreadToken(nullptr, DuplicatedCurrentProcessToken))
                    {
                        if (OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &CurrentProcessToken))
                        {
                            if (GetTokenInformation(CurrentProcessToken, TokenSessionId, &SessionID, sizeof(DWORD), &ReturnLength))
                            {

                                HANDLE ProcessHandle = INVALID_HANDLE_VALUE;
                                HRESULT hr = OpenLsassProcess(MAXIMUM_ALLOWED, FALSE, &ProcessHandle);
                                if (hr == S_OK)
                                {
                                    hr = OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, &OriginalLsassProcessToken) ? S_OK : S_FALSE;

                                    CloseHandle(ProcessHandle);
                                }

                                if (hr == S_OK)
                                {
                                    if (DuplicateTokenEx(OriginalLsassProcessToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenImpersonation, &SystemToken))
                                    {
                                        if (AdjustTokenAllPrivileges(SystemToken, SE_PRIVILEGE_ENABLED))
                                        {
                                            if (SetThreadToken(nullptr, SystemToken))
                                            {
                                                hr = OpenServiceProcessToken(L"TrustedInstaller", MAXIMUM_ALLOWED, &OriginalToken);
                                                if (hr == S_OK)
                                                {
                                                    if (DuplicateTokenEx(OriginalToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &hToken))
                                                    {
                                                        if (SetTokenInformation(hToken, TokenSessionId, (PVOID)&SessionID, sizeof(DWORD)))
                                                        {
                                                            if (AdjustTokenAllPrivileges(hToken, SE_PRIVILEGE_ENABLED))
                                                            {
                                                                TOKEN_MANDATORY_LABEL TML{};
                                                                SID_IDENTIFIER_AUTHORITY SIA = SECURITY_MANDATORY_LABEL_AUTHORITY;

                                                                if (AllocateAndInitializeSid(&SIA, 1, MandatoryLabelRid, 0, 0, 0, 0, 0, 0, 0, &TML.Label.Sid))
                                                                {
                                                                    TML.Label.Attributes = SE_GROUP_INTEGRITY;

                                                                    BOOL b = SetTokenInformation(hToken, TokenIntegrityLevel, &TML, sizeof(TML));

                                                                    FreeSid(TML.Label.Sid);

                                                                    if (b)
                                                                    {
                                                                        DWORD dwCreationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;

                                                                        STARTUPINFOW StartupInfo = { 0 };
                                                                        PROCESS_INFORMATION ProcessInfo = { 0 };

                                                                        StartupInfo.cb = sizeof(STARTUPINFOW);

                                                                        StartupInfo.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");

                                                                        StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
                                                                        StartupInfo.wShowWindow = static_cast<WORD>(ShowWindowMode);

                                                                        LPVOID lpEnvironment = nullptr;

                                                                        LPWSTR ExpandedString = nullptr;

                                                                        if (CreateEnvironmentBlock(&lpEnvironment, hToken, TRUE))
                                                                        {
                                                                            if (ExpandEnvironmentStringsWithMemory(CommandLine, &ExpandedString))
                                                                            {
                                                                                if (CreateProcessAsUserW(
                                                                                    hToken,
                                                                                    nullptr,
                                                                                    ExpandedString,
                                                                                    nullptr,
                                                                                    nullptr,
                                                                                    FALSE,
                                                                                    dwCreationFlags,
                                                                                    lpEnvironment,
                                                                                    CurrentDirectory,
                                                                                    &StartupInfo,
                                                                                    &ProcessInfo))
                                                                                {
                                                                                    SetPriorityClass(ProcessInfo.hProcess, ProcessPriority);

                                                                                    ResumeThread(ProcessInfo.hThread);

                                                                                    WaitForSingleObjectEx(ProcessInfo.hProcess, 0, FALSE);

                                                                                    CloseHandle(ProcessInfo.hProcess);
                                                                                    CloseHandle(ProcessInfo.hThread);
                                                                                }

                                                                                HeapFree(GetProcessHeap(), 0, ExpandedString);
                                                                            }

                                                                            DestroyEnvironmentBlock(lpEnvironment);
                                                                        }

                                                                        return TRUE;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return FALSE;
}

