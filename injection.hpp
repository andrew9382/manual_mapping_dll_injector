#pragma once

#include "start_routine.hpp"

// cloaking options:
#define INJ_ERASE_HEADER            0x01 // replaces first 1000 bytes of the dll with 0`s (high priority than INJ_FAKE_HEADER)
#define INJ_FAKE_HEADER             0x02 // replaces original dll header with ntdll.dll header
#define INJ_UNLINK_FROM_PEB         0x04
#define INJ_SCRAMBLE_DLL_NAME       0x08
#define INJ_LOAD_DLL_COPY           0x20

// thread cloaking options (ignored if launch method not NtCreateThreadEx): 
#define INJ_CTX_HIDE_FROM_DEBUGGER  0x0040
#define INJ_CTX_FAKE_THREAD_ID      0x0080
#define INJ_CTX_FAKE_START_ADDRESS  0x0100
#define INJ_CTX_SKIP_TRHEAD_ATTACH  0x0200

#define INJ_CTX_ALL (INJ_CTX_HIDE_FROM_DEBUGGER | INJ_CTX_FAKE_THREAD_ID | INJ_CTX_FAKE_START_ADDRESS | INJ_CTX_SKIP_TRHEAD_ATTACH)

#define INJ_BY_PROCESS_ID				0x0400
#define INJ_BY_PROCESS_NAME				0x0800
#define INJ_BY_HANDLE_HIJACK_AND_NAME	0x2000
#define INJ_BY_HANDLE_HIJACK_AND_ID		0x4000
#define INJ_BY_HANDLE					0x8000

enum class INJECTION_MODE
{
	IM_MANUAL_MAPPING,
	IM_LOAD_LIBRARY_EX_W
};

enum class INJ_GET_HANDLE_METHOD
{
	IGHM_BY_PROCESS_ID,
	IGHM_BY_PROCESS_NAME,
	IGHM_BY_HANDLE_HIJACK,
	IGHM_BY_HANDLE
};

struct INJECTION_DATA
{
	DWORD					out								= 0;
	HMODULE					h_dll_out						= 0;
	BYTE					data_buf[0x500]					= { 0 };
	wchar_t					dll_path[MAX_PATH]				= { 0 };
	INJECTION_MODE			mode							= INJECTION_MODE::IM_MANUAL_MAPPING;
	DWORD					flags							= 0;
	LAUNCH_METHOD			method							= LAUNCH_METHOD::LM_THREAD_HIJACK;

	struct START_ARGS
	{
		HINSTANCE hinstance = 0;
	} start_args;
};

DWORD Inject(INJECTION_DATA* data);
DWORD HijackHandle(INJECTION_DATA* data, ACCESS_MASK desired_access, DWORD target_pid);