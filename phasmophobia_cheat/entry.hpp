#include "includes.hpp"
#include <wininet.h>

namespace entry
{
	auto initialize(void*) -> void;
}

auto __stdcall DllMain(void*, uint32_t call_reason, void*) -> bool;