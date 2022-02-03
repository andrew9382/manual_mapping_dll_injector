#pragma once

DWORD GetProcId(const wchar_t* proc_name);

DWORD GetOwnModulePathW(wchar_t* mod_name_buf, size_t buf_size);

bool FileExists(const wchar_t* file_path);

bool VerifyDLL(const wchar_t* file_path, WORD desired_machine);

bool IsNativeProcess(HANDLE h_proc);