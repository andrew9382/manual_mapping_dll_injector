#pragma once

// cloaking options:
#define INJ_ERASE_HEADER            0x01 // replaces first 1000 bytes of the dll with 0`s (high priority than INJ_FAKE_HEADER)
#define INJ_FAKE_HEADER             0x02 // replaces original dll header with ntdll.dll header
#define INJ_UNLINK_FROM_PEB         0x04
#define INJ_THREAD_CREATE_CLOAKED   0x08
#define INJ_SCRAMBLE_DLL_NAME       0x10
#define INJ_HANDLE_HIJACKING        0x20
#define INJ_LOAD_DLL_COPY           0x40
// ignored if using manual mapping or launch method not NtCreateThreadEx

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
	LAUNCH_METHOD   method					   = LAUNCH_METHOD::LM_THREAD_HIJACK;
	DWORD			out						   = 0;
};

bool Inject(INJECTION_DATA* data);