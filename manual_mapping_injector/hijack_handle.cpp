#include "includes.hpp"

bool EnumProcessHandles(std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* out_proc_handles_vec)
{
	if (!out_proc_handles_vec)
	{
		return false;
	}

	if (!out_proc_handles_vec->empty())
	{
		out_proc_handles_vec->clear();
	}

	size_t size = PAGE_SIZE * 5;
	size_t size_out = 0;

	BYTE* handles_buf = new BYTE[size];

	if (!handles_buf)
	{
		return false;
	}

	while (NATIVE::NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemHandleInformation, handles_buf, size, (ULONG*)&size_out) == STATUS_INFO_LENGTH_MISMATCH)
	{
		delete[size] handles_buf;

		size = size_out + PAGE_SIZE;
		handles_buf = new BYTE[size];

		if (!handles_buf)
		{
			return false;
		}
	}

	SYSTEM_HANDLE_INFORMATION* handle_info = (SYSTEM_HANDLE_INFORMATION*)handles_buf;
	size_t handles_count = handle_info->NumberOfHandles;

	if (!handles_count)
	{
		delete[size] handles_buf;

		return false;
	}

	SYSTEM_HANDLE_TABLE_ENTRY_INFO* handle_entry = handle_info->Handles;
	for (DWORD i = 0; i < handles_count; ++i, ++handle_entry)
	{
		if ((OBJECT_TYPE_NUMBER)handle_entry->ObjectTypeIndex == OBJECT_TYPE_NUMBER::Process)
		{
			out_proc_handles_vec->push_back(*handle_entry);
		}
	}

	delete[size] handles_buf;

	return true;
}

bool FindProcessHandles(const std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO>* sys_handles_vec, DWORD target_pid, std::vector<HANDLE_INFO>* out_proc_handles_vec, ACCESS_MASK desired_access)
{
	if (!sys_handles_vec || sys_handles_vec->empty() || !out_proc_handles_vec)
	{
		return false;
	}

	if (!out_proc_handles_vec->empty())
	{
		out_proc_handles_vec->clear();
	}

	for (auto& h_info : *sys_handles_vec)
	{
		WORD current_pid = h_info.UniqueProcessId;

		if (current_pid == target_pid || current_pid == GetCurrentProcessId())
		{
			continue;
		}

		if (desired_access != HJ_HANDLE_ANY_ACCESS && (h_info.GrantedAccess & desired_access) != desired_access)
		{
			continue;
		}

		HANDLE h_current_proc = OpenProcess(PROCESS_DUP_HANDLE, NULL, current_pid);
		if (!h_current_proc)
		{
			continue;
		}

		HANDLE src_handle = (HANDLE)h_info.HandleValue;
		HANDLE dst_handle = 0;
		if (!DuplicateHandle(h_current_proc, src_handle, GetCurrentProcess(), &dst_handle, PROCESS_QUERY_LIMITED_INFORMATION, NULL, NULL))
		{
			CloseHandle(h_current_proc);

			continue;
		}

		if (GetProcessId(dst_handle) != target_pid)
		{
			CloseHandle(h_current_proc);
			
			CloseHandle(dst_handle);

			continue;
		}

		CloseHandle(h_current_proc);

		CloseHandle(dst_handle);

		HANDLE_INFO hi = { 0 };

		hi.granted_access = h_info.GrantedAccess;
		hi.handle = (HANDLE)h_info.HandleValue;
		hi.owner_pid = h_info.UniqueProcessId;

		out_proc_handles_vec->push_back(hi);
	}

	return true;
}