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
#include <filesystem>
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
#include "start_routine.hpp"
#include "hijack_handle.hpp"
#include "injection.hpp"
#include "hook_scanner.hpp"
#include "import_handler.hpp"
#include "manual_map.hpp"
#include "symbol_loader.hpp"
#include "symbol_parser.hpp"
#include "externs.hpp"
#include "inject_internal.hpp"
#include "namespaces.hpp"
#include "veh_shell.hpp"

#pragma warning(disable: 4201) // unnamed union (nt structures)
#pragma warning(disable: 4324) // structure member alignment resulting in additional bytes being added as padding
#pragma warning(disable: 6001) // uninitialized memory & handles (false positive in for loops with continue statements)
#pragma warning(disable: 6258) // TerminateThread warning
#pragma warning(disable: 4996) // some deprications