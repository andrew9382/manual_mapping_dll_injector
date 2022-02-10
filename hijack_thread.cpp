#include "includes.hpp"

DWORD ThreadHijack(HANDLE h_proc, f_Routine routine, void* arg_routine, DWORD* out, DWORD timeout)
{
	if (!h_proc || !routine || !arg_routine || !out || !timeout)
	{
		return 0;
	}

	ProcessInfo PI;

	if (!PI.SetProcess(h_proc))
	{
		ERRLOG("ThreadHijack: SetProcess error");

		return 0;
	}

	DWORD ThreadId = 0;
	do
	{
		THREAD_STATE state;
		KWAIT_REASON reason;
		
		if (!PI.GetThreadState(&state, &reason) || reason == KWAIT_REASON::WrQueue)
		{
			continue;
		}

		if (!PI.IsThreadWorkerThread() && (PI.IsThreadInAlertableState() || state == THREAD_STATE::Running) && PI.GetTID() != GetCurrentThreadId())
		{
			ThreadId = PI.GetTID();

			break;
		}
	
	} while (PI.NextThread());

	if (!ThreadId)
	{
		ERRLOG("ThreadHijack: no compatible thread found");
	
		return 0;
	}

	HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, NULL, ThreadId);
	if (!h_thread)
	{
		ERRLOG("ThreadHijack: OpenThread: %d", GetLastError());

		return 0;
	}

	if (SUSP_ERR(SuspendThread(h_thread)))
	{
		ERRLOG("ThreadHijack: SuspendThread: %d", GetLastError());

		CloseHandle(h_thread);

		return 0;
	}

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(h_thread, &ctx))
	{
		ERRLOG("ThreadHijack: GetThreadContext: %d", GetLastError());

		ResumeThread(h_thread);
		CloseHandle(h_thread);

		return 0;
	}

	void* shellcode_loc = VirtualAllocEx(h_proc, NULL, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!shellcode_loc)
	{
		ERRLOG("ThreadHijack: VirtualAllocEx: %d", GetLastError());

		ResumeThread(h_thread);
		CloseHandle(h_thread);

		return 0;
	}

	void* shellcode_data = VirtualAllocEx(h_proc, NULL, sizeof(SR_REMOTE_DATA), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!shellcode_data)
	{
		ERRLOG("ThreadHijack: VirtualAllocEx: %d", GetLastError());
		
		VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);

		ResumeThread(h_thread);
		CloseHandle(h_thread);

		return 0;
	}

	SR_REMOTE_DATA data;

	ZeroMem(&data);

	data.routine			= routine;
	data.arg_routine		= arg_routine;

	if (!WriteProcessMemory(h_proc, shellcode_data, &data, sizeof(data), NULL))
	{
		ERRLOG("ThreadHijack: WriteProcessMemory: %d", GetLastError());

		ResumeThread(h_thread);
		
		VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);

		CloseHandle(h_thread);

		return 0;
	}

#ifdef _WIN64
#else
	BYTE shellcode[] =
	{
		0x83, 0xEC, 0x04,                           // sub esp, 0x04
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,   // mov [esp], old_eip           ; save old eip into stack to return

		0x53, 0x52, 0x50, 0x51,                     // push e(b/d/a/c)x
		0x9C,										// pushfd

		0xBA, 0x00, 0x00, 0x00, 0x00,				// mov edx, SR_REMOTE_DATA
		
		0xC6, 0x02, 0x01,							// mov BYTE PTR [edx], 0x01     ; SR_WR_EXECUTING
		
		0x52,										// push edx                     ; save edx
		0xFF, 0x72, 0x08,							// push [edx + 0x08]            ; push arg to f_Routine
		0xFF, 0x52, 0x0C,							// call DWORD PTR [edx + 0x0C]  ; call f_Routine
		0x5A,										// pop edx                      ; restore edx
		0x89, 0x42, 0x10,							// mov [edx + 0x10], eax        ; store returned value

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,			// mov eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,							// mov eax, [eax + 0x34]
		0x89, 0x42, 0x04,							// mov [edx + 0x04], eax        ; save last error

		0xC6, 0x02, 0x02,							// mov BYTE PTR [edx], 0x02     ; SR_WR_EXECUTING_FINISHED
		
		0x9D,										// popfd
		0x59, 0x58, 0x5A, 0x5B,						// pop e(c/a/d/b)x
		0xC3										// ret                          ; return to old eip
	};

	DWORD old_eip = ctx.Eip;
	*(DWORD*)(shellcode + 0x06) = old_eip;
	*(DWORD*)(shellcode + 0x10) = (DWORD)shellcode_data;

	ctx.Eip = (DWORD)shellcode_loc;

#endif

	if (!WriteProcessMemory(h_proc, shellcode_loc, shellcode, sizeof(shellcode), NULL))
	{
		ERRLOG("ThreadHijack: WriteProcessMemory: %d", GetLastError());

		ResumeThread(h_thread);

		VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);

		CloseHandle(h_thread);

		return 0;
	}

	if (!SetThreadContext(h_thread, &ctx))
	{
		ERRLOG("ThreadHijack: SetThreadContext: %d", GetLastError());

		ResumeThread(h_thread);
		
		VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);
		
		CloseHandle(h_thread);

		return 0;
	}

	if (SUSP_ERR(ResumeThread(h_thread)))
	{
		ERRLOG("ThreadHijack: SetThreadContext: %d", GetLastError());

#ifdef _WIN64
		ctx.Rip = old_rip;
#else
		ctx.Eip = old_eip;
#endif
		SetThreadContext(h_thread, &ctx);

		ResumeThread(h_thread);
		
		VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
		VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);
		
		CloseHandle(h_thread);

		return 0;
	}

	ULONGLONG time = GetTickCount64();
	while (GetTickCount64() - time < timeout)
	{
		if (!ReadProcessMemory(h_proc, shellcode_data, &data, sizeof(data), NULL))
		{
			ERRLOG("ThreadHijack: ReadProcessMemory: %d", GetLastError());

#ifdef _WIN64
			ctx.Rip = old_rip;
#else
			ctx.Eip = old_eip;
#endif
			if (!SUSP_ERR(SuspendThread(h_thread)) && SetThreadContext(h_thread, &ctx) && !SUSP_ERR(ResumeThread(h_thread)))
			{
				VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
				VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);
			}

			CloseHandle(h_thread);

			return 0;
		}
		
		if (data.status == SR_WORK_STATUS::WS_EXECUTING_FINISHED)
		{
			break;
		}
	}

	if (data.status != SR_WORK_STATUS::WS_EXECUTING_FINISHED)
	{
		if (data.status == SR_WORK_STATUS::WS_PENDING)
		{
			ERRLOG("ThreadHijack: shellcode execute timeout");
#ifdef _WIN64
			ctx.Rip = old_rip;
#else
			ctx.Eip = old_eip;
#endif
			if (!SUSP_ERR(SuspendThread(h_thread)) && SetThreadContext(h_thread, &ctx) && !SUSP_ERR(ResumeThread(h_thread)))
			{
				VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
				VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);
			}

			CloseHandle(h_thread);

			return 0;
		}

		ERRLOG("ThreadHijack: timeout");

		CloseHandle(h_thread);
		
		return 0;
	}

	*out = data.ret;

	VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
	VirtualFreeEx(h_proc, shellcode_loc, NULL, MEM_RELEASE);

	CloseHandle(h_thread);

	printf("[ SUCCESS ] ThreadHijack: execution finished\n");

	return 1;
}