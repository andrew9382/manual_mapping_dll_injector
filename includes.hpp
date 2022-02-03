#pragma once

#include <Windows.h>
#include <WinInet.h>
#include <dbghelp.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <vector>
#include <locale>
#include <codecvt>
#include <map>
#include <string>
#include "NT Defs.h"
#include "NT Funcs.h"
#include "Win10.h"
#include "Win8.h"
#include "Win7.h"
#include "Win81.h"
#include "Win11.h"
#include "globals.hpp"
#include "tools.hpp"
#include "process_info.hpp"
#include "interface.hpp"
#include "injection.hpp"
#include "import_handler.hpp"
#include "some_defines.hpp"
#include "manual_map.hpp"
#include "symbol_loader.hpp"
#include "start_routine.hpp"
#include "symbol_parser.hpp"

#pragma warning(disable: 4201) // unnamed union (nt structures)
#pragma warning(disable: 4324) // structure member alignment resulting in additional bytes being added as padding
#pragma warning(disable: 6001) // uninitialized memory & handles (false positive in for loops with continue statements)
#pragma warning(disable: 6258) // TerminateThread warning
#pragma warning(disable: 4996) // codecvt deprication