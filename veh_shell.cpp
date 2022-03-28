#include "includes.hpp"

LONG CODE_SEG(".veh$1") CALLBACK VEHShell(EXCEPTION_POINTERS* EP)
{
	volatile auto* data = (VEH_SHELL_DATA*)(VEH_DATA_SIG32);
	EXCEPTION_REGISTRATION_RECORD* ex_reg_rec = (EXCEPTION_REGISTRATION_RECORD*)__readfsdword(0x00);

	if (!ex_reg_rec)
	{
		return 0;
	}

	RTL_INVERTED_FUNCTION_TABLE_ENTRY* entry = nullptr;

	if (data->os_version == g_Win7)
	{
		entry = &((RTL_INVERTED_FUNCTION_TABLE_WIN7*)data->_LdrpInvertedFunctionTable)->Entries[0];
	}
	else
	{
		entry = &data->_LdrpInvertedFunctionTable->Entries[0];
	}

	for (DWORD i = 0; i < data->_LdrpInvertedFunctionTable->Count; ++i)
	{
		if (entry[i].ImageBase == data->image_base)
		{
			entry = &entry[i];

			break;
		}
	}

	DWORD ptr_dec = DecodeSystemPtr((DWORD)entry->ExceptionDirectory);

	DWORD* start = (DWORD*)ptr_dec;

	if (data->os_version >= g_Win81)
	{
		data->_LdrProtectMrdata(FALSE);
	}

	for (; ex_reg_rec && ex_reg_rec != (EXCEPTION_REGISTRATION_RECORD*)(0xFFFFFFFF) && ex_reg_rec->Next != (EXCEPTION_REGISTRATION_RECORD*)(0xFFFFFFFF); ex_reg_rec = ex_reg_rec->Next)
	{
		if ((BYTE*)ex_reg_rec->Handler < data->image_base || (BYTE*)ex_reg_rec->Handler >= data->image_base + data->image_size)
		{
			continue;
		}

		bool new_handler = false;

		for (DWORD* rva = start; rva != nullptr && rva < start + 0x100; ++rva)
		{
			if (*rva == 0)
			{
				*rva = (DWORD)ex_reg_rec->Handler - (DWORD)entry->ImageBase;
				
				++entry->ExceptionDirectorySize;

				new_handler = true;

				break;
			}
			else if (*rva == (DWORD)ex_reg_rec->Handler - (DWORD)entry->ImageBase)
			{
				break;
			}
		}

		if (new_handler)
		{
			for (DWORD i = 0; i < entry->ExceptionDirectorySize; ++i)
			{
				for (DWORD j = entry->ExceptionDirectorySize - 1; j > i; --j)
				{
					if (start[j - 1] > start[j])
					{
						start[j - 1] ^= start[j];
						start[j] ^= start[j - 1];
						start[j - 1] ^= start[j];
					}
				}
			}
		}
	}

	if (data->os_version >= g_Win81)
	{
		data->_LdrProtectMrdata(TRUE);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG CODE_SEG(".veh$2") CALLBACK VEHShell_End()
{
	return 0;
}