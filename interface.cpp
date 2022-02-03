#include "includes.hpp"

void Interface::WorkLoop()
{
	while (true)
	{
		KEY last_key = GetLastKey();
	}
}

KEY Interface::GetLastKey()
{
	for (KEY key = 8; key < 190; ++key)
		if (GetAsyncKeyState(key))
			return key;
	return 0;
}

bool Interface::PushInFile()
{
	return false;
}

bool Interface::PopFromFile()
{
	return false;
}

bool Interface::GetFromFile()
{
	return false;
}
