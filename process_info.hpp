#pragma once

#define PI_INIT_BUFFER_SIZE 0x10000

#define LDR_LIST_ENTRY_HEAD_OFFSET (sizeof(ULONG) + sizeof(ULONG) + sizeof(HANDLE))

#define NtUserMsgWaitForMultipleObjectsEx_INDEX_IN_ARRAY 4

#define NT_RET_OFFSET_64_WIN7		0x0A //Win7 - Win10 1507
#define NT_RET_OFFSET_64_WIN10_1511 0x14 //Win10 1511+

#define NT_RET_OFFSET_86_WIN7 0x15 //Win7 only
#define NT_RET_OFFSET_86_WIN8 0x0C //Win8+

#define TEB_SameTebFlags_64 0x17EE
#define TEB_SameTebFlags_86 0xFCA

#define TEB_SAMETEB_FLAGS_LoaderWorker 0x2000

#ifdef _WIN64
#define TEB_SameTebFlags TEB_SameTebFlags_64
#else
#define TEB_SameTebFlags TEB_SameTebFlags_86
#endif

struct _MODULE_INFO
{
	std::shared_ptr<wchar_t[]>	module_name			= { 0 };
	size_t						module_name_len		= 0;
	HMODULE						module_base			= 0;
	PVOID						module_entry		= 0;

	_MODULE_INFO& operator=(_MODULE_INFO& other);
};

class ProcessInfo
{
private:

	SYSTEM_PROCESS_INFORMATION* first_process   = nullptr;
	SYSTEM_PROCESS_INFORMATION* current_process = nullptr;
	SYSTEM_THREAD_INFORMATION*  current_thread  = nullptr;

	f_NtQueryInformationProcess NtQueryInformationProcess = nullptr;
	f_NtQueryInformationThread  NtQueryInformationThread  = nullptr;
	f_NtQuerySystemInformation  NtQuerySystemInformation  = nullptr;

	HANDLE	 h_current_process		= NULL;
	HMODULE  h_win32u				= NULL;
	DWORD	 current_thread_index	= NULL;
	DWORD	 buffer_size			= NULL;
	
	std::vector<_MODULE_INFO*> process_modules;

	DWORD wait_functions_address[5] = { 0 };

	void ClearModulesVec();

public:

	ProcessInfo();
	~ProcessInfo();

	//bool SetProcessByName(const wchar_t* proc_name, DWORD desired_access);
	bool SetProcess(HANDLE h_target_proc);
	bool SetThread(DWORD TID);

	bool FirstThread();
	bool NextThread();

	bool RefreshInformation();

	DWORD GetPID();
	DWORD GetTID();
	
	bool IsProtectedProcess();

	void* GetTEBaddr();
	void* GetPEBaddr();

	bool ReadAllModules();
	bool GetModuleInfo(const wchar_t* mod_name, _MODULE_INFO* out_module);
	HMODULE _GetModuleHandle(const wchar_t* mod_name);

	bool IsThreadInAlertableState();
	bool IsThreadWorkerThread();
	bool GetThreadState(THREAD_STATE* state, KWAIT_REASON* reason);
	
	const SYSTEM_PROCESS_INFORMATION* GetProcessInfo();
	const SYSTEM_THREAD_INFORMATION* GetThreadInfo();
};