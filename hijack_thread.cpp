#include "includes.hpp"

DWORD ThreadHijack(HANDLE h_proc, f_Routine routine, void* arg, DWORD* out, DWORD timeout)
{
	ProcessInfo PI;

	if (!PI.SetProcess(h_proc))
	{
		printf("[ERROR] ThreadHijack: set process error\n");

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
		printf("[ERROR] ThreadHijack: no compatible thread found\n");
	
		return 0;
	}

	HANDLE h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, NULL, ThreadId);
	if (!h_thread)
	{
		printf("[ERROR] ThreadHijack: OpenThread: %d\n", GetLastError());

		return 0;
	}

	if (!SuspendThread(h_thread))
	{
		printf("[ERROR] ThreadHijack: SuspendThread: %d\n", GetLastError());

		CloseHandle(h_thread);

		return 0;
	}

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(h_thread, &ctx))
	{
		printf("[ERROR] ThreadHijack: GetThreadContext: %d\n", GetLastError());

		ResumeThread(h_thread);
		CloseHandle(h_thread);

		return 0;
	}

	void* shellcode_data = VirtualAllocEx(h_proc, NULL, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!shellcode_data)
	{
		printf("[ERROR] ThreadHijack: VirtualAllocEx: %d\n", GetLastError());

		ResumeThread(h_thread);
		CloseHandle(h_thread);

		return 0;
	}

#ifdef _WIN64
#else
	BYTE shellcode[] =
	{
		SR_REMOTE_DATA_PLACEHOLDER

		0x83, 0xEC, 0x04,                           // sub esp, 0x04
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,   // mov [esp], old_eip           ; save old eip into stack to return

		0x53, 0x52, 0x50, 0x51,                     // push e(b/d/a/c)x
		0x9C,										// pushfd

		0xBA, 0x00, 0x00, 0x00, 0x00,				// mov edx, SR_REMOTE_DATA
		
		0xC6, 0x02, 0x01,							// mov BYTE PTR [edx], 0x01     ; SR_WR_EXECUTING

		0xFF, 0x72, 0x08,							// push [edx + 0x08]            ; push arg to f_Routine
		0xFF, 0x52, 0x0C,							// call DWORD PTR [edx + 0x0C]  ; call f_Routine
		0x89, 0x42, 0x10,							// mov [edx + 0x10], eax        ; store returned value

		0x64, 0x8B, 0x40, 0x18,						// mov eax, fs:[eax + 0x18]     ; GetLastError
		0x8B, 0x40, 0x34,							// mov eax, [eax + 0x34]
		0x89, 0x42, 0x04,							// mov [edx + 0x04], eax        ; save last error

		0xC6, 0x02, 0x02,							// mov BYTE PTR [edx], 0x02     ; SR_WR_EXECUTING_FINISHED

		0x59, 0x58, 0x5A, 0x5B,						// pop e(c/a/d/b)x
		0x9D,										// popfd
		0xC3										// ret                          ; return to old eip
	};
	
	SR_REMOTE_DATA data;
	data.routine = routine;
	data.arg = arg;

	memcpy(shellcode, (void*)&data, sizeof(data));
	DWORD old_eip = ctx.Eip;
	*(DWORD*)(shellcode + 0x06 + sizeof(SR_REMOTE_DATA)) = old_eip;
	*(DWORD*)(shellcode + 0x10 + sizeof(SR_REMOTE_DATA)) = (DWORD)shellcode_data;

	DWORD shellcode_entry = (DWORD)shellcode_data + sizeof(SR_REMOTE_DATA);
	ctx.Eip = shellcode_entry;

#endif

	if (!WriteProcessMemory(h_proc, shellcode_data, shellcode, sizeof(shellcode), NULL))
	{
		printf("[ERROR] ThreadHijack: WriteProcessMemory: %d\n", GetLastError());

		ResumeThread(h_thread);
		VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
		CloseHandle(h_thread);

		return 0;
	}

	if (!SetThreadContext(h_thread, &ctx))
	{
		printf("[ERROR] ThreadHijack: SetThreadContext: %d\n", GetLastError());

		ResumeThread(h_thread);
		VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
		CloseHandle(h_thread);

		return 0;
	}

	if (ResumeThread(h_thread) == (DWORD)-1)
	{
		printf("[ERROR] ThreadHijack: SetThreadContext: %d\n", GetLastError());

#ifdef _WIN64
		ctx.Rip = old_rip;
#else
		ctx.Eip = old_eip;
#endif
		SetThreadContext(h_thread, &ctx);

		ResumeThread(h_thread);
		VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
		CloseHandle(h_thread);

		return 0;
	}

	ULONGLONG time = GetTickCount64();
	while (GetTickCount64() - time < timeout)
	{
		if (!ReadProcessMemory(h_proc, shellcode_data, &data, sizeof(data), NULL))
		{
			printf("[ERROR] ThreadHijack: ReadProcessMemory: %d\n", GetLastError());

#ifdef _WIN64
			ctx.Rip = old_rip;
#else
			ctx.Eip = old_eip;
#endif
			if (SuspendThread(h_thread) != (DWORD)-1 && SetThreadContext(h_thread, &ctx) && ResumeThread(h_thread) != (DWORD)-1)
			{
				VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
			}

			CloseHandle(h_thread);

			return 0;
		}
		
		if (data.status == SR_WORK_STATUS::WS_EXECUTING_FINISHED || data.status == SR_WORK_STATUS::WS_PENDING)
		{
			break;
		}
	}

	if (data.status != SR_WORK_STATUS::WS_EXECUTING_FINISHED)
	{
		if (data.status == SR_WORK_STATUS::WS_PENDING)
		{
			printf("[ERROR] ThreadHijack: shellcode execute timeout\n");
#ifdef _WIN64
			ctx.Rip = old_rip;
#else
			ctx.Eip = old_eip;
#endif
			if (SuspendThread(h_thread) != (DWORD)-1 && SetThreadContext(h_thread, &ctx) && ResumeThread(h_thread) != (DWORD)-1)
			{
				VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
			}

			CloseHandle(h_thread);

			return 0;
		}

		printf("[ERROR] ThreadHijack: timeout\n");

		CloseHandle(h_thread);
		
		return 0;
	}

	*out = data.ret;

	VirtualFreeEx(h_proc, shellcode_data, NULL, MEM_RELEASE);
	CloseHandle(h_thread);

	printf("[SUCCESS] ThreadHijack: execution finished\n");

	return 1;
}

void __declspec(naked) shell()
{
	__asm
	{
		sub esp, 0x04
		mov DWORD PTR [esp], 0xCCCCCCCC
		push ebx
		push edx
		push eax
		push ecx
		pushfd
		mov edx, 0xCCCCCCCC
		mov [edx], 0x01
		push [edx + 0x08]
		call DWORD PTR [edx + 0x0C]
		mov [edx + 0x10], eax
		mov eax, fs:[eax + 0x18]
		mov eax, [eax + 0x34]
		mov [edx + 0x04], eax
		mov [edx], 0x02
		pop ecx
		pop eax
		pop edx
		pop ebx
		popfd
		ret
	}
}