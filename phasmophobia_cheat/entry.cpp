#include "entry.hpp"
#include "minhook/MinHook.h"

#include <intrin.h>

auto entry::initialize(void* dll_base) -> void
{
	/* noto: i patched the dll locally, did not patch it in the mapper
	* at first i patched login menu call
	* patched auth check
	* patched player.update() hook auth check
	* patched enzo::http_send_request
	*/ 

	HRSRC resource = FindResourceA(reinterpret_cast<HMODULE>(dll_base), (LPCSTR)101, "cheat_bin");
	HGLOBAL loaded_resource = LoadResource(reinterpret_cast<HMODULE>(dll_base), resource);
	size_t size = SizeofResource(reinterpret_cast<HMODULE>(dll_base), resource);
	uint8_t* binary = reinterpret_cast<uint8_t*>(LockResource(loaded_resource));

	printf("[ * ] copying image...\n");

	auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(binary + reinterpret_cast<IMAGE_DOS_HEADER*>(binary)->e_lfanew);
	auto optional_header = &nt_header->OptionalHeader;
	auto file_header = &nt_header->FileHeader;

	void* allocated = VirtualAlloc(0, optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!allocated)
		return;

	memcpy(allocated, binary, 0x1000);

	auto section_header = IMAGE_FIRST_SECTION(nt_header);
	for (UINT idx = 0; idx != file_header->NumberOfSections; ++idx, ++section_header)
	{
		if (section_header->SizeOfRawData)
		{
			memcpy(reinterpret_cast<void*>((uint64_t)allocated + section_header->VirtualAddress), binary + section_header->PointerToRawData, section_header->SizeOfRawData);
		}
	}

	printf("[ * ] image copied\n");
	printf("[ * ] relocating image\n");

	uint8_t* delta = (uint8_t*)allocated - optional_header->ImageBase;

	if (delta)
	{
		if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			auto* reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>((uint64_t)allocated + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* reloc_end = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(reloc_data) + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

			while (reloc_data < reloc_end && reloc_data->SizeOfBlock)
			{
				UINT count_of_entries = (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* relative_info = reinterpret_cast<WORD*>(reloc_data + 1);

				for (UINT idx = 0; idx != count_of_entries; ++idx, ++relative_info)
				{
					if (((*relative_info >> 0x0C) == IMAGE_REL_BASED_DIR64))
					{
						UINT_PTR* relocation_address = reinterpret_cast<UINT_PTR*>((uint64_t)allocated + reloc_data->VirtualAddress + ((*relative_info) & 0xFFF));
						*relocation_address += reinterpret_cast<UINT_PTR>(delta);
					}
				}

				reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(reloc_data) + reloc_data->SizeOfBlock);
			}
		}
	}

	printf("[ * ] image relocated\n");
	printf("[ * ] fixing imports...\n");

	if (optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>((uint64_t)allocated + optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (import_descriptor->Name)
		{
			char* module_name = reinterpret_cast<char*>((uint64_t)allocated + import_descriptor->Name);
			HINSTANCE module_address = LoadLibraryA(module_name);

			ULONG_PTR* thunk_ref = reinterpret_cast<ULONG_PTR*>((uint64_t)allocated + import_descriptor->OriginalFirstThunk);
			ULONG_PTR* function_ref = reinterpret_cast<ULONG_PTR*>((uint64_t)allocated + import_descriptor->FirstThunk);

			if (!thunk_ref)
				thunk_ref = function_ref;

			for (; *thunk_ref; ++thunk_ref, ++function_ref)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref))
				{
					*function_ref = (ULONG_PTR)GetProcAddress(module_address, reinterpret_cast<char*>(*thunk_ref & 0xFFFF));
				}
				else
				{
					auto* p_import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>((uint64_t)allocated + (*thunk_ref));
					*function_ref = (ULONG_PTR)GetProcAddress(module_address, p_import->Name);
				}
			}

			++import_descriptor;
		}
	}

	printf("[ * ] imports fixed\n");
	printf("[ * ] calling dllmain...\n");

	int(__stdcall* dll_entry_point)(void*, uint32_t, void*) = (decltype(dll_entry_point))((uint64_t)allocated + optional_header->AddressOfEntryPoint);
	dll_entry_point(allocated, 1, 0);

	printf("[ * ] dllmain callled, pwned by peheader & bytearray\n");
}

auto __stdcall DllMain(void* dll_base, uint32_t call_reason, void* reserved_value) -> bool
{
	if (call_reason != 1)
		return false;

	AllocConsole();
	freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
	freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
	SetConsoleTitleA("[ project enzo crack??? ]");
	
	CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entry::initialize), dll_base, 0, 0);
	return true;
}