#pragma once

#define NT_FUNC(func) inline f_##func func = nullptr
#define NT_LOCAL(func) f_##func func = nullptr
#define INIT_CONSTRUCTOR_NATIVE(func) func = NATIVE::##func

#define WIN32_FUNC(func) inline decltype(func)* p_##func = nullptr
#define WIN32_LOCAL(func) decltype(func)* p_##func = nullptr
#define INIT_WIN32_FUNC(func, h_k32) NATIVE::p_##func = (decltype(func)*)GetProcAddress(h_k32, #func)
#define INIT_CONSTRUCTOR_NATIVE_WIN32(func) p_##func = NATIVE::p_##func

#define _FUNC_(func) L#func, NATIVE::##func

#define g_Win8	62
#define g_Win7	61
#define g_Win81	63
#define g_Win10	100
#define g_Win11	100

#define g_Win7_SP1   7601
#define g_Win8_SP1   9600
#define g_Win10_1507 10240
#define g_Win10_1511 10586
#define g_Win10_1607 14393
#define g_Win10_1703 15063
#define g_Win10_1709 16299
#define g_Win10_1803 17134
#define g_Win10_1809 17763
#define g_Win10_1903 18362
#define g_Win10_1909 18363
#define g_Win10_2004 19041
#define g_Win10_20H2 19042
#define g_Win10_21H1 19043
#define g_Win10_21H2 19044
#define g_Win11_21H2 22000

inline DWORD g_os_version;
inline DWORD g_os_build_number;

DWORD GetOSVersion();
DWORD GetOSBuildVersion();

bool IsWin7OrGreater();
bool IsWin8OrGreater();
bool IsWin81OrGreater();
bool IsWin10OrGreater();
bool IsWin11OrGreater();

enum class IMPORT_INDEX
{
	II_NTDLL,
	II_KERNEL32
};

namespace NATIVE
{
	NT_FUNC(NtQueryObject);
	NT_FUNC(LdrGetProcedureAddress);
	NT_FUNC(LdrLoadDll);
	NT_FUNC(LdrUnloadDll);
	NT_FUNC(RtlFreeHeap);
	NT_FUNC(LdrpHeap);
	NT_FUNC(RtlAllocateHeap);
	NT_FUNC(NtAllocateVirtualMemory);
	NT_FUNC(NtFreeVirtualMemory);
	NT_FUNC(memmove);
	NT_FUNC(NtOpenFile);
	NT_FUNC(NtClose);
	NT_FUNC(NtSetInformationFile);
	NT_FUNC(NtQueryInformationFile);
	NT_FUNC(NtReadFile);
	NT_FUNC(LdrLockLoaderLock);
	NT_FUNC(LdrUnlockLoaderLock);

	WIN32_FUNC(LoadLibraryA);
	WIN32_FUNC(FreeLibrary);
}

bool ResolveImports(class SymbolLoader* loader);