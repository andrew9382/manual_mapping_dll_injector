#pragma once

#define HJ_HANDLE_ANY_ACCESS -1

struct HANDLE_INFO
{
	ACCESS_MASK		granted_access	= 0;
	DWORD			owner_pid		= 0;
	HANDLE			handle			= 0;
};

bool EnumProcessHandles(std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* out_proc_handles_vec);
bool FindProcessHandles(const std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* sys_handles_vec, DWORD target_pid, std::vector<HANDLE_INFO>* out_proc_handles_vec, ACCESS_MASK desired_access);