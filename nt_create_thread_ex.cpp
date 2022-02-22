#include "includes.hpp"

void CODE_SEG(".nt_thrd$1") __stdcall NtCreateThreadEx_Shellcode(SR_REMOTE_DATA* data);
void CODE_SEG(".nt_thrd$2") __stdcall NtCreateThreadEx_Shellcode_End();

DWORD _NtCreateThreadEx(HANDLE h_proc, f_Routine routine, DWORD flags, void* arg_routine, DWORD* out, DWORD timeout)
{
	if (!h_proc || !routine || !arg_routine || !out || !timeout)
	{
		return 0;
	}

	ProcessInfo PI;

	if (!PI.SetProcess(h_proc))
	{
		return 0;
	}

	void* fake_start_addr = nullptr;
	if (flags & INJ_CTX_FAKE_START_ADDRESS)
	{
		fake_start_addr = (void*)PI.GetEntryPoint();
		
		if (!fake_start_addr)
		{
			return 0;
		}
	}

	DWORD thread_id = 0;
	if (flags & INJ_CTX_FAKE_THREAD_ID)
	{
		thread_id = PI.GetTID();

		if (!thread_id)
		{
			return 0;
		}
	}

	DWORD nt_flags = 0;

	if (flags & INJ_CTX_HIDE_FROM_DEBUGGER)
	{
		nt_flags |= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	}

	if (flags & INJ_CTX_SKIP_TRHEAD_ATTACH)
	{
		nt_flags |= THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH;
	}

	if (fake_start_addr)
	{
		nt_flags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
	}

	void* remote_func_data = VirtualAllocEx(h_proc, NULL, sizeof(SR_REMOTE_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!remote_func_data)
	{
		return 0;
	}

	SR_REMOTE_DATA data;
	
	ZeroMem(&data);
	
	data.routine = routine;
	data.arg_routine = arg_routine;
	data.arg_remote_func = (void*)thread_id;

	if (!WriteProcessMemory(h_proc, remote_func_data, &data, sizeof(data), NULL))
	{
		VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);

		return 0;
	}

	size_t remote_func_size = (DWORD)NtCreateThreadEx_Shellcode_End - (DWORD)NtCreateThreadEx_Shellcode;

	void* remote_func = VirtualAllocEx(h_proc, NULL, remote_func_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!remote_func)
	{
		VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);

		return 0;
	}

	if (!WriteProcessMemory(h_proc, remote_func, NtCreateThreadEx_Shellcode, remote_func_size, NULL))
	{
		VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, remote_func, NULL, MEM_RELEASE);
	
		return 0;
	}

	HANDLE h_thread = 0;
	if (NT_FAIL(NATIVE::NtCreateThreadEx(&h_thread, THREAD_ALL_ACCESS, NULL, h_proc, fake_start_addr ? fake_start_addr : remote_func, remote_func_data, nt_flags, NULL, NULL, NULL, NULL)) || !h_thread)
	{
		VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, remote_func, NULL, MEM_RELEASE);

		return 0;
	}

	if (fake_start_addr)
	{
		bool failed = false;

		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_INTEGER;

		if (!GetThreadContext(h_thread, &ctx))
		{
			failed = true;
			goto FAIL;
		}

#ifdef _WIN64
		ctx.Rcx = (DWORD64)remote_func;
#else
		ctx.Eax = (DWORD)remote_func;
#endif

		if (!SetThreadContext(h_thread, &ctx))
		{
			failed = true;
			goto FAIL;
		}

		if (SUSP_ERR(ResumeThread(h_thread)))
		{
			failed = true;
		}

		FAIL:
		if (failed)
		{
			TerminateThread(h_thread, 0);

			VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);
			VirtualFreeEx(h_proc, remote_func, NULL, MEM_RELEASE);

			return 0;
		}
	}

	LOG("%d", GetThreadId(h_thread));

	DWORD wait_ret = WaitForSingleObject(h_thread, timeout);
	if (wait_ret != WAIT_OBJECT_0)
	{
		TerminateThread(h_thread, 0);

		VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, remote_func, NULL, MEM_RELEASE);

		return 0;
	}

	VirtualFreeEx(h_proc, remote_func, NULL, MEM_RELEASE);

	if (!ReadProcessMemory(h_proc, remote_func_data, &data, sizeof(data), NULL))
	{
		VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);

		return 0;
	}

	VirtualFreeEx(h_proc, remote_func_data, NULL, MEM_RELEASE);

	if (data.status != SR_WORK_STATUS::WS_EXECUTING_FINISHED)
	{
		return 0;
	}

	*out = data.ret;

	return 1;
}

void CODE_SEG(".nt_thrd$1") __stdcall NtCreateThreadEx_Shellcode(SR_REMOTE_DATA* data)
{
	if (!data)
	{
		return;
	}

	data->status = SR_WORK_STATUS::WS_EXECUTING;

#ifdef _WIN64
	TEB* teb = (TEB*)__readgsqword(0x30);
#else
	TEB* teb = (TEB*)__readfsdword(0x18);
#endif

	HANDLE tid = data->arg_remote_func;

	if (tid)
	{
#ifdef _WIN64
		__writegsqword(0x48, (DWORD)tid);
#else
		__writefsdword(0x24, (DWORD)tid);
#endif
		teb->Cid.UniqueThread = tid;
		teb->RealClientId.UniqueThread = tid;
	}

	data->ret = data->routine(data->arg_routine);

#ifdef _WIN64
	data->last_error = __readgsqword(0x68);
#else 
	data->last_error = __readfsdword(0x34);
#endif

	data->status = SR_WORK_STATUS::WS_EXECUTING_FINISHED;

	return;
}

void CODE_SEG(".nt_thrd$2") __stdcall NtCreateThreadEx_Shellcode_End()
{
	return;
}