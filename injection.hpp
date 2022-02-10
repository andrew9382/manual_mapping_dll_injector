#pragma once

// cloaking options:
#define INJ_ERASE_HEADER            0x01 // replaces first 1000 bytes of the dll with 0`s (high priority than INJ_FAKE_HEADER)
#define INJ_FAKE_HEADER             0x02 // replaces original dll header with ntdll.dll header
#define INJ_UNLINK_FROM_PEB         0x04
#define INJ_SCRAMBLE_DLL_NAME       0x08
#define INJ_HANDLE_HIJACKING        0x10
#define INJ_LOAD_DLL_COPY           0x20

// thread cloaking options: 
#define INJ_CTX_HIDE_FROM_DEBUGGER  0x0040
#define INJ_CTX_FAKE_THREAD_ID      0x0080
#define INJ_CTX_FAKE_START_ADDRESS  0x0100
#define INJ_CTX_SKIP_TRHEAD_ATTACH  0x0200

#define INJ_CTX_ALL (INJ_CTX_HIDE_FROM_DEBUGGER | INJ_CTX_FAKE_THREAD_ID | INJ_CTX_FAKE_START_ADDRESS | INJ_CTX_SKIP_TRHEAD_ATTACH)
// ignored if using manual mapping or launch method not NtCreateThreadEx

enum class LAUNCH_METHOD;

enum class INJECTION_MODE
{
	IM_MANUAL_MAPPING,
	IM_LOAD_LIBRARY_EX_W
};

struct INJECTION_DATA
{
	DWORD           proc_id                    = 0;
	wchar_t         proc_name  [MAX_PATH]      = { 0 };
	wchar_t         dll_path   [MAX_PATH]      = { 0 };
	INJECTION_MODE  mode					   = INJECTION_MODE::IM_MANUAL_MAPPING;
	DWORD           flags                      = 0;
	HANDLE          h_proc                     = 0;     // optional
	HMODULE         h_out_dll                  = 0;
	LAUNCH_METHOD   method;
	DWORD			out						   = 0;
};

bool Inject(INJECTION_DATA* data);