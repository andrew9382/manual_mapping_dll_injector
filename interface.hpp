#pragma once

using KEY = DWORD;

#define VK_1 0x31
#define VK_2 0x32

class Interface
{
private:
	std::ifstream	file;
	std::wstring	dll_name;
	std::wstring	window_name;
public:
	struct
	{
		HANDLE	h_proc;
		bool	thread_hijacking;
		bool	create_remote_thread;
	};
	
	void WorkLoop();
private:
	KEY GetLastKey();
	bool PushInFile();
	bool PopFromFile();
	bool GetFromFile();
};