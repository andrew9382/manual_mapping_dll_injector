#pragma once

// broken

//#define PTR_64_ARR 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//#define PTR_86_ARR 0x00, 0x00, 0x00, 0x00,
//
//#define SR_REMOTE_DATA_PLACEHOLDER_64 PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR
//#define SR_REMOTE_DATA_PLACEHOLDER_86 PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR
//
//#ifdef _WIN64
//#define SR_REMOTE_DATA_PLACEHOLDER SR_REMOTE_DATA_PLACEHOLDER_64
//#else
//#define SR_REMOTE_DATA_PLACEHOLDER SR_REMOTE_DATA_PLACEHOLDER_86
//#endif

using f_Routine = DWORD(__stdcall*)(void* arg_routine);

enum class SR_WORK_STATUS : DWORD
{
	WS_PENDING             = 0,
	WS_EXECUTING           = 1,
	WS_EXECUTING_FINISHED  = 2
};

enum class LAUNCH_METHOD
{
	LM_THREAD_HIJACK,
	LM_FAKE_VEH,
	LM_QUEUE_USER_APC,
	LM_NT_CREATE_THREAD_EX
};

struct SR_REMOTE_DATA
{
	SR_WORK_STATUS  status			= SR_WORK_STATUS::WS_PENDING;
	DWORD           last_error		= 0;
	void*           arg_routine		= nullptr;
	f_Routine       routine			= nullptr;
	DWORD           ret				= 0;
	void*			arg_remote_func = nullptr;
	
};

DWORD StartRoutine(LAUNCH_METHOD method, HANDLE h_proc, f_Routine routine, DWORD flags, void* arg_routine, DWORD* out, DWORD timeout);

DWORD ThreadHijack(HANDLE h_proc, f_Routine routine, void* arg_routine, DWORD* out, DWORD timeout);
DWORD _NtCreateThreadEx(HANDLE h_proc, f_Routine routine, DWORD flags, void* arg_routine, DWORD* out, DWORD timeout);