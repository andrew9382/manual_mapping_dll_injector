#include "includes.hpp"

DWORD StartRoutine(LAUNCH_METHOD method, HANDLE h_proc, f_Routine routine, DWORD flags, void* arg_routine, DWORD* out, DWORD timeout)
{
	switch (method)
	{
	case LAUNCH_METHOD::LM_THREAD_HIJACK:
		return ThreadHijack(h_proc, routine, arg_routine, out, timeout);

	//case LAUNCH_METHOD::LM_FAKE_VEH:

	case LAUNCH_METHOD::LM_NT_CREATE_THREAD_EX:
		return _NtCreateThreadEx(h_proc, routine, flags, arg_routine, out, timeout);

	//case LAUNCH_METHOD::LM_QUEUE_USER_APC:

	};
}