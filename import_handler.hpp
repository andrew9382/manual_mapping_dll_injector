#pragma once

#define NT_FUNC(func) inline f_##func func = nullptr
#define NT_LOCAL(func) f_##func func = nullptr
#define INIT_CONSTRUCTOR_NATIVE(func) func = NATIVE::##func

#define WIN32_FUNC(func) inline decltype(func)* p_##func = nullptr
#define WIN32_LOCAL(func) decltype(func)* p_##func = nullptr
#define INIT_WIN32_FUNC(func, h_k32) NATIVE::p_##func = (decltype(func)*)GetProcAddress(h_k32, #func)
#define INIT_CONSTRUCTOR_NATIVE_WIN32(func) p_##func = NATIVE::p_##func

#define _FUNC_(func) L#func, NATIVE::##func

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