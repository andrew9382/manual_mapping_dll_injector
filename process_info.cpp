#include "includes.hpp"
#include "process_info.hpp"

#define NEXT_SYSTEM_PROCESS_ENTRY(entry) ((SYSTEM_PROCESS_INFORMATION*)((BYTE*)entry + entry->NextEntryOffset))

ProcessInfo::ProcessInfo()
{
	HMODULE h_NTDLL = GetModuleHandle(L"ntdll.dll");

	if (!h_NTDLL)
	{
		h_NTDLL = LoadLibrary(L"ntdll.dll");
		
		if (!h_NTDLL)
			throw std::exception("[ERROR] ProcessInfo(): can`t get HMODULE of ntdll.dll");
	}

	buffer_size = PI_INIT_BUFFER_SIZE;

	NtQueryInformationProcess  =  (f_NtQueryInformationProcess) GetProcAddress(h_NTDLL, "NtQueryInformationProcess");
	NtQueryInformationThread   =  (f_NtQueryInformationThread)  GetProcAddress(h_NTDLL, "NtQueryInformationThread");
	NtQuerySystemInformation   =  (f_NtQuerySystemInformation)  GetProcAddress(h_NTDLL, "NtQuerySystemInformation");

	if (!NtQueryInformationProcess || !NtQueryInformationThread || !NtQuerySystemInformation)
		throw std::exception("[ERROR] ProcessInfo(): can`t get address of ntdll.dll function(s)");

	DWORD nt_ret_offset = NULL;

#ifdef _WIN64
	if (GetOSBuildVersion() <= g_Win10_1507)
		nt_ret_offset = NT_RET_OFFSET_64_WIN7;
	else
		nt_ret_offset = NT_RET_OFFSET_64_WIN10_1511;
#else
	if (GetOSVersion() == g_Win7)
		nt_ret_offset = NT_RET_OFFSET_86_WIN7;
	else
		nt_ret_offset = NT_RET_OFFSET_86_WIN8;
#endif

	wait_functions_address[0] = (DWORD)GetProcAddress(h_NTDLL, "NtDelayExecution"               ) + nt_ret_offset;
	wait_functions_address[1] = (DWORD)GetProcAddress(h_NTDLL, "NtWaitForSingleObject"          ) + nt_ret_offset;
	wait_functions_address[2] = (DWORD)GetProcAddress(h_NTDLL, "NtWaitForMultipleObjects"       ) + nt_ret_offset;
	wait_functions_address[3] = (DWORD)GetProcAddress(h_NTDLL, "NtSignalAndWaitForSingleObject" ) + nt_ret_offset;

	for (auto& el : wait_functions_address)
	{
		if (!el)
			throw std::exception("[ERROR] ProcessInfo(): can`t get address of ntdll.dll function(s)");
	}
		
	if (GetOSBuildVersion() >= g_Win10_1607)
	{
		h_win32u = LoadLibrary(L"win32u.dll");
		
		if (!h_win32u)
			throw std::exception("[ERROR] ProcessInfo(): can`t get HMODULE of win32u.dll");

		wait_functions_address[4] = (DWORD)GetProcAddress(h_win32u, "NtUserMsgWaitForMultipleObjectsEx") + nt_ret_offset;
		
		if (!wait_functions_address[4])
			throw std::exception("[ERROR] ProcessInfo(): can`t get address of ntdll.dll NtUserMsgWaitForMultipleObjectsEx function");
	}
}

ProcessInfo::~ProcessInfo()
{
	if (h_win32u)
		FreeLibrary(h_win32u);

	if (first_process)
		delete[buffer_size] first_process;
}

//bool ProcessInfo::SetProcessByName(const wchar_t* proc_name, DWORD desired_access)
//{
//	if (!proc_name)
//		return false;
//
//	if (!first_process)
//	{
//		if (!RefreshInformation())
//			return false;
//	}
//
//	while (NEXT_SYSTEM_PROCESS_ENTRY(current_process) != current_process)
//	{
//		if (!_wcsicmp(current_process->ImageName.szBuffer, proc_name))
//			break;
//
//		current_process = NEXT_SYSTEM_PROCESS_ENTRY(current_process);
//	}
//
//	if (_wcsicmp(current_process->ImageName.szBuffer, proc_name))
//	{
//		h_current_process    = NULL;
//		current_process      = first_process;
//		current_thread_index = NULL;
//		current_thread       = &current_process->Threads[NULL];
//
//		return false;
//	}
//
//	h_current_process = OpenProcess(desired_access, NULL, (DWORD)current_process->UniqueProcessId);
//	if (!h_current_process)
//	{
//		h_current_process    = NULL;
//		current_process      = first_process;
//		current_thread_index = NULL;
//		current_thread       = &current_process->Threads[NULL];
//
//		return false;
//	}
//	
//	current_thread_index = NULL;
//	current_thread = &current_process->Threads[NULL];
//
//	return true;
//}

bool ProcessInfo::SetProcess(HANDLE h_target_proc)
{
	DWORD handle_info = NULL;
	if (!h_target_proc || h_target_proc == INVALID_HANDLE_VALUE || !GetHandleInformation(h_target_proc, &handle_info))
		return false;

	if (!first_process)
	{
		if (!RefreshInformation())
			return false;
	}

	DWORD target_pid = GetProcessId(h_target_proc);
	
	while (NEXT_SYSTEM_PROCESS_ENTRY(current_process) != current_process)
	{
		if ((DWORD)current_process->UniqueProcessId == target_pid)
			break;

		current_process = NEXT_SYSTEM_PROCESS_ENTRY(current_process);
	}

	if ((DWORD)current_process->UniqueProcessId != target_pid)
	{
		current_process		 = first_process;
		current_thread_index = NULL;
		current_thread       = &current_process->Threads[NULL];

		return false;
	}

	h_current_process    = h_target_proc;
	current_thread_index = NULL;
	current_thread       = &current_process->Threads[NULL];

	return true;
}

bool ProcessInfo::SetThread(DWORD TID)
{
	if (!current_process)
		return false;
	
	current_thread = nullptr;
	
	for (DWORD i = 0; i < current_process->NumberOfThreads; ++i)
	{
		if ((DWORD)current_process->Threads[i].ClientId.UniqueThread == TID)
		{
			current_thread = &current_process->Threads[i];
			current_thread_index = i;

			break;
		}
	}

	if (current_thread == nullptr)
	{
		current_thread = &current_process->Threads[NULL];
		current_thread_index = NULL;

		return false;
	}
	
	return true;
}

bool ProcessInfo::FirstThread()
{
	if (!current_process)
		return false;

	current_thread = &current_process->Threads[NULL];
	current_thread_index = NULL;

	return true;
}

bool ProcessInfo::NextThread()
{
	if (!current_process)
		return false;

	if (current_thread_index == current_process->NumberOfThreads - 1)
		return false;

	current_thread = &current_process->Threads[++current_thread_index];

	return true;
}

bool ProcessInfo::RefreshInformation()
{
	if (first_process)
	{
		delete[buffer_size] first_process;
		first_process = nullptr;
	
		return RefreshInformation();
	}
	else
	{
		first_process = (SYSTEM_PROCESS_INFORMATION*)new BYTE[buffer_size];
		
		if (!first_process)
			return false;
	}

	ULONG size_out = NULL;
	NTSTATUS status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, first_process, buffer_size, &size_out);
	
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		delete[buffer_size] first_process;
		buffer_size = size_out + PAGE_SIZE;

		first_process = (SYSTEM_PROCESS_INFORMATION*)new BYTE[buffer_size];
		
		if (!first_process)
			return false;

		status = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, first_process, buffer_size, &size_out);
	}

	if (NT_FAIL(status))
	{
		delete[buffer_size] first_process;
		first_process     = nullptr;
		h_current_process = NULL;

		return false;
	}

	h_current_process = NULL;
	current_process   = first_process;
	current_thread    = &first_process->Threads[NULL];

	return true;
}

DWORD ProcessInfo::GetPID()
{
	if (!current_process)
		return NULL;

	return GetProcessId(h_current_process);
}

DWORD ProcessInfo::GetTID()
{
	if (!current_thread)
		return NULL;

	return MDWD(current_thread->ClientId.UniqueThread);
}

bool ProcessInfo::IsProtectedProcess()
{
	BYTE info = NULL;

	if (NT_FAIL(NtQueryInformationProcess(h_current_process, PROCESSINFOCLASS::ProcessProtectionInformation, &info, sizeof(info), NULL)))
		return true;

	return (info != NULL);
}

void* ProcessInfo::GetTEB()
{
	if (!current_thread)
		return nullptr;

	HANDLE h_thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | THREAD_QUERY_INFORMATION, NULL, GetTID());
	
	if (!h_thread)
		return nullptr;

	THREAD_BASIC_INFORMATION TBI = { 0 };
	NTSTATUS status = NtQueryInformationThread(h_thread, THREADINFOCLASS::ThreadBasicInformation, &TBI, sizeof(TBI), NULL);

	CloseHandle(h_thread);

	if (NT_FAIL(status))
		return nullptr;

	return TBI.TebBaseAddress;
}

bool ProcessInfo::IsThreadInAlertableState()
{
	if (!current_thread)
		return false;

	HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT, NULL, GetTID());
	if (!h_thread)
		return false;

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(h_thread, &ctx))
	{
		CloseHandle(h_thread);

		return false;
	}

	CloseHandle(h_thread);

#ifdef _WIN64
#else
	if (!ctx.Eip || !ctx.Esp)
		return false;

	DWORD stack[6] = { 0 };
	if (!ReadProcessMemory(h_current_process, (void*)ctx.Esp, stack, sizeof(stack), NULL))
		return false;

	if (ctx.Eip == wait_functions_address[0]) // NtDelayExecution
	{
		if (GetOSVersion() == g_Win7)
			return stack[2] == true;
		else
			return stack[1] == true;
	}
	else if (ctx.Eip == wait_functions_address[1]) // NtWaitForSingleObject
	{
		if (GetOSVersion() == g_Win7)
			return stack[3] == true;
		else
			return stack[2] == true;
	}
	else if (ctx.Eip == wait_functions_address[2]) // NtWaitForMultipleObjects
	{
		if (GetOSVersion() == g_Win7)
			return stack[5] == true;
		else
			return stack[4] == true;
	}
	else if (ctx.Eip == wait_functions_address[3]) //NtSignalAndWaitForSingleObject
	{
		if (GetOSVersion() == g_Win7)
			return stack[4] == true;
		else
			return stack[3] == true;
	}
	else if (ctx.Eip == wait_functions_address[4]) //NtUserMsgWaitForMultipleObjectsEx
		return (stack[5] & MWMO_ALERTABLE) != 0;
#endif

	return true;
}

bool ProcessInfo::IsThreadWorkerThread()
{
	if (GetOSVersion() < g_Win10 || !current_thread)
		return false;

	BYTE* TEB = (BYTE*)GetTEB();
	if (!TEB)
		return false;

	WORD teb_info;
	if (!ReadProcessMemory(h_current_process, TEB + TEB_SameTebFlags, &teb_info, sizeof(teb_info), NULL))
		return false;

	return (teb_info & TEB_SAMETEB_FLAGS_LoaderWorker) != 0;
}

bool ProcessInfo::GetThreadState(THREAD_STATE* state, KWAIT_REASON* reason)
{
	if (!current_thread || !state || !reason)
		return false;

	*state = current_thread->ThreadState;
	*reason = current_thread->WaitReason;

	return true;
}

const SYSTEM_PROCESS_INFORMATION* ProcessInfo::GetProcessInfo()
{
	return current_process ? current_process : nullptr;
}

const SYSTEM_THREAD_INFORMATION* ProcessInfo::GetThreadInfo()
{
	return current_thread ? current_thread : nullptr;
}