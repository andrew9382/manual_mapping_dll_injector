#pragma once

#define VEH_DATA_SIG32 0x77777777
#define VEH_DATA_SIG64 0x1488133714881337

#ifdef _WIN64
#define VEH_DATA_SIG VEH_DATA_SIG64
#else
#define VEH_DATA_SIG VEH_DATA_SIG32
#endif

// i use this fucking crutch because a compiler does some shit with volatile pointer to VEH_SHELL_DATA in the VEHShell function
__forceinline bool FindAndReplacePointers(BYTE* start, size_t len, UINT_PTR signature, UINT_PTR value)
{
	if (!start || !len)
	{
		return false;
	}

	BYTE* _start = start;

	bool found = false;

	for (; start < (_start + len) - sizeof(UINT_PTR);)
	{
		found = true;
		DWORD i = 0;

		for (; start[i] == ((BYTE*)&signature)[(sizeof(UINT_PTR) - 1) - i] && i < sizeof(UINT_PTR); ++i);

		if (i < sizeof(UINT_PTR) / 2)
		{
			found = false;
		}

		if (found)
		{
			DWORD offset = (*(DWORD*)(start - (sizeof(UINT_PTR) - i))) - signature;

			*(DWORD*)(start - (sizeof(UINT_PTR) - i)) = value + offset;

			start += i;
		}
		else
		{
			++start;
		}
	}

	return true;
}

struct VEH_SHELL_DATA
{
	DWORD os_version	= 0;
	BYTE* image_base	= 0;
	DWORD image_size	= 0;

	f_LdrProtectMrdata				_LdrProtectMrdata;
	f_LdrpInvertedFunctionTable		_LdrpInvertedFunctionTable;
};

LONG CODE_SEG(".veh$1") CALLBACK VEHShell(EXCEPTION_POINTERS* EP);
LONG CODE_SEG(".veh$2") CALLBACK VEHShell_End();