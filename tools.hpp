#pragma once

DWORD GetProcId(const wchar_t* proc_name);

DWORD GetOwnModuleFullPathW(fs::path& mod_name_path);

bool VerifyDLL(const wchar_t* file_path, WORD desired_machine);

bool IsNativeProcess(HANDLE h_proc);

DWORD IsElevatedProcess(HANDLE h_proc);

int _random(int begin, int end);