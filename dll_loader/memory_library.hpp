/*
	Author:	Easton
	Date:	2013/02/27

	This is a very powerful memory implementation of LoadLibrary.
	The library not only entitles the loaded library to call GetModuleFileName, but also patches and bypasses the exception handling validation,
	which means that developers can still use try/catch scenarios as what loaded by LoadLibrary does.
	The faculties described above both support x86 and x64, as well as thread safe.
*/

#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <custom/hookapi.hpp>
#include <map>
#include <filesystem>
#include "codepage.hpp"
#include "runtime_context.hpp"

class memory_library
{
#define	MemoryLibraryGuid				L"DC7FDDF7-B2F1-4B99-BE6A-AA683FF11CE6"		//The unique guid key identifying the following map.
#define	ExceptionValidationBypassGuid	L"131C8113-E083-4C7F-BEAF-82D73B01F2C5"
	typedef	map<HMODULE, pair<size_t, wstring>>	ModuleMap;							//Holds all the registered memory DLLs.

private:
	static vector<char> read_file(const std::experimental::filesystem::path& p)
	{
		using namespace std;
		ifstream file(p.wstring(), ios::binary);
		auto size = std::experimental::filesystem::file_size(p);
		vector<char> buffer((size_t)size);
		if (0 < size)
			file.read(buffer.data(), size);
		file.close();
		return buffer;
	}
	static wstring get_module_path(HMODULE module)
	{
		if(module_exists(module))
			return get_instance_information(module).second;
		return L"";
	}
#ifdef _WIN64
	static PRUNTIME_FUNCTION NTAPI MyLookupFunctionEntry(_In_ DWORD64 ControlPc, _Out_ PDWORD64 ImageBase, _Inout_opt_ PUNWIND_HISTORY_TABLE HistoryTable)
	{
		auto rf = hookapi::call_origin_by_hook(MyLookupFunctionEntry)(ControlPc, ImageBase, HistoryTable);
		if(nullptr == rf)
		{
			size_t handler_count;
			
			auto table = MyLookupFunctionTable((PVOID)ControlPc, reinterpret_cast<HINSTANCE*>(ImageBase), &handler_count);
			if(nullptr == table) return table;
			ControlPc -= (DWORD64)*ImageBase;
			for(size_t index = 0; index < handler_count; ++index)
			{
				auto& scopeRecord = table[index];
				if(ControlPc >= scopeRecord.BeginAddress && ControlPc < scopeRecord.EndAddress) return &scopeRecord;
			}
		}
		return rf;
	}
	//API interception desired to produce SEHHandlerTable and handler entry count of memory instance.
	//This hook only exists in x64 systems.
	static PRUNTIME_FUNCTION WINAPI MyLookupFunctionTable(PVOID Handler, HINSTANCE* ImageBase, SIZE_T* HandlerCount)
	{
		auto instance = address_in_memory_modules(Handler);

		if(nullptr != instance)
		{
			auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(instance);
			auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<char*>(instance) + dos_header->e_lfanew);
			auto section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt_header + 1);
			auto directory = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			*ImageBase = instance;
			*HandlerCount = directory->Size;
			return reinterpret_cast<PRUNTIME_FUNCTION>(reinterpret_cast<char*>(instance) + directory->VirtualAddress);
		}
		else
		{
			static auto RtlLookupFunctionTable = GetProcAddress(GetModuleHandle(L"ntdll"), "RtlLookupFunctionTable");
			if(nullptr != RtlLookupFunctionTable)
				return reinterpret_cast<PRUNTIME_FUNCTION(WINAPI*)(PVOID, HINSTANCE*, SIZE_T*)>(RtlLookupFunctionTable)(Handler, ImageBase, HandlerCount);
			else
				return nullptr;
		}
		//	return hookapi::call_origin_by_hook(MyLookupFunctionTable)(Handler, ImageBase, HandlerCount);	//Call the origin RtlLookupFunctionTable to obtain the origin effect.
	}
	static PVOID WINAPI MyPcToFileHeader( _In_ PVOID PcValue, _Out_ PVOID * BaseOfImage )
	{
		auto address = address_in_memory_modules(PcValue);
		if(nullptr != address)
			return *BaseOfImage = address;
		else
			return hookapi::call_origin_by_hook(MyPcToFileHeader)(PcValue, BaseOfImage);
	}
#else
	//Causing the IsValidHandler to return true. Only affects the x86 systems.
	static LONG WINAPI MyQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, long MemoryInformationClass, PVOID MemoryInformation, ULONG MemoryInformationLength, PULONG ReturnLength)
	{
		if(nullptr != address_in_memory_modules(BaseAddress))
			return -1;
		return hookapi::call_origin_by_hook(MyQueryVirtualMemory)(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	}
#endif // _WIN64

	//mimic the GetModuleFileName calling.
	static DWORD WINAPI MyGetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
	{
		if(nullptr != hModule && module_exists(hModule))
		{
			auto path = get_module_path(hModule);
			wcscpy_s(lpFilename, nSize, path.c_str());
			return (DWORD)path.size();
		}
		return hookapi::call_origin(GetModuleFileNameW)(hModule, lpFilename, nSize);
	}

	static DWORD WINAPI MyGetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
	{
		if(nullptr != hModule && module_exists(hModule))
		{
			auto path = codepage::unicode_to_acp(get_module_path(hModule));
			strcpy_s(lpFilename, nSize, path.c_str());
			return (DWORD)path.size();
		}
		return hookapi::call_origin(GetModuleFileNameA)(hModule, lpFilename, nSize);		
	}
	//Check if an arbitrary pointer is inside one of the memory modules. If it is, then the correspondent instance will be returned.
	static HINSTANCE address_in_memory_modules(void* address)
	{
		auto modules = get_module_map();
		for(auto it = modules->begin(); modules->end() != it; ++it)
			if(it->first <= address && reinterpret_cast<const char*>(it->first) + (it->second.first) > address) return it->first;
		return nullptr;
	}
	static pair<size_t, wstring>& get_instance_information(HINSTANCE instance)
	{
		auto modules = get_module_map();
		return modules->find(instance)->second;
	}
	//Checks if the instance is registered.
	static bool module_exists(HMODULE instance)
	{
		auto modules = get_module_map();
		return modules->end() != modules->find(instance);
	}
	static shared_ptr<ModuleMap> get_module_map()
	{
		static shared_ptr<ModuleMap> cached_map_ptr = nullptr;
		if(nullptr == cached_map_ptr)
			cached_map_ptr = runtime_context::process::create_or_get_ptr<ModuleMap>(MemoryLibraryGuid);
		return cached_map_ptr;
	}
	//Sets the path of the loaded module.
	static void set_moudle_path(HMODULE instance, const wstring& path)
	{
		get_instance_information(instance).second = path;
	}
	//Removes memory module information from the context map. It's only called by free function.
	static void remove_memory_module_to_list(HINSTANCE instance)
	{
		get_module_map()->erase(instance);
	}
	//This routine will be performed each time calling load or load_from_file.
	static void patch_module_system()
	{
		if(false == runtime_context::process::exists(ExceptionValidationBypassGuid))
		{
			if(false == hookapi::is_hooked(GetModuleFileNameW))
				hookapi::hook(GetModuleFileNameW, MyGetModuleFileNameW);
			if(false == hookapi::is_hooked(GetModuleFileNameA))
				hookapi::hook(GetModuleFileNameA, MyGetModuleFileNameA);

#ifdef _WIN64
			auto RtlLookupFunctionEntry = GetProcAddress(GetModuleHandle(L"ntdll"), "RtlLookupFunctionEntry");
			if(nullptr != RtlLookupFunctionEntry)
				hookapi::hook_unsafe(RtlLookupFunctionEntry, MyLookupFunctionEntry);
			auto RtlPcToFileHeader = GetProcAddress(GetModuleHandle(L"ntdll"), "RtlPcToFileHeader");
			hookapi::hook_unsafe(RtlPcToFileHeader, MyPcToFileHeader);
#else
			auto NtQueryVirtualMemory = GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryVirtualMemory");
			if(false == hookapi::is_hooked(NtQueryVirtualMemory))
				hookapi::hook_unsafe(NtQueryVirtualMemory, MyQueryVirtualMemory);
#endif // _WIN64
			runtime_context::process::set_value(ExceptionValidationBypassGuid, 1);
		}
	}
public:
	//Register a memory module.
	static void add_memory_module_to_list(HMODULE instance)
	{
		patch_module_system();
		auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(instance);
		auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<char*>(instance) + dos_header->e_lfanew);
		auto modules = get_module_map();
		(*modules)[instance] = make_pair(nt_header->OptionalHeader.SizeOfImage, wstring(L""));
	}
	//Load a library from file system, like LoadLibrary.
	static HINSTANCE load_from_file(const wstring& path, void* parameter = nullptr)
	{
		try{
			return load(read_file(path), parameter, path);
		}
		catch(...)
		{
			return nullptr;
		}
	}
	//find a module by its name.
	static HINSTANCE find(const wstring& name)
	{
		auto modules = get_module_map();
		auto filename = std::experimental::filesystem::path(name).filename().wstring();
		for(auto it = modules->begin(); modules->end() != it; ++it)
		{
			auto modulename = std::experimental::filesystem::path(it->second.second).filename().wstring();
			if(boost::iequals(filename, modulename))
				return it->first;
		}
		return nullptr;
	}
	//Load a dll from memory buffer.
	static HINSTANCE load(const vector<char>& buffer, void* parameter = nullptr, const wstring& path = L"")
	{
		if(0 == buffer.size()) return nullptr;
		runtime_context::thread::set_value(L"memory_library_file", &buffer);
		return load(&buffer[0], parameter, path);
	}
	//The raw pointer version for load memory dll.
	static HINSTANCE load(const void* buffer, void* parameter = nullptr, const wstring& path = L"")
	{
		IMAGE_DOS_HEADER*			dos_header;
		IMAGE_NT_HEADERS*			nt_header;
		DWORD						offset;
		IMAGE_BASE_RELOCATION*		reloc_item;
		LPWORD						reloc_entry;
		DWORD						reloc_address;
		DWORD						reloc_number;
		PSIZE_T						thunk_data;
		IMAGE_IMPORT_DESCRIPTOR*	import_descriptor;
		LPBYTE						base;
		HINSTANCE					dll;
		SIZE_T						api;
		LPVOID						entry_point;
		BOOL						main_result;
		char*						name;

		base = const_cast<LPBYTE>(reinterpret_cast<const BYTE*>(buffer));
		dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
		base = reinterpret_cast<BYTE*>(VirtualAlloc(nullptr, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE));
		memcpy(base, buffer, nt_header->OptionalHeader.SizeOfHeaders);
		copy_section(base, buffer);
		offset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		import_descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(&base[offset]);
		while(import_descriptor->TimeDateStamp || import_descriptor->FirstThunk || import_descriptor->Name || import_descriptor->OriginalFirstThunk || import_descriptor->ForwarderChain)
		{
			offset = import_descriptor->Name;
			dll = find(codepage::acp_to_unicode(reinterpret_cast<const char*>(&base[offset])));
			if(nullptr == dll)
				dll = LoadLibraryA(reinterpret_cast<const char*>(&base[offset]));
			if(nullptr != dll)
			{
				offset = import_descriptor->FirstThunk;
				const SIZE_T HIGHEST_MARK = SIZE_T(1) << (sizeof(SIZE_T) * 8 - 1);
				while(thunk_data = reinterpret_cast<PSIZE_T>(&base[offset]))
				{
					if(0 == *thunk_data) break;
					if(HIGHEST_MARK & *thunk_data)
					{
						api = (SIZE_T)GetProcAddress(dll, MAKEINTRESOURCEA(*thunk_data ^ HIGHEST_MARK));
					}
					else
					{
						name = reinterpret_cast<char*>(&base[*thunk_data]) + sizeof(WORD);
						api = (SIZE_T)GetProcAddress(dll, name);
					}
					*reinterpret_cast<PSIZE_T>(&base[offset]) = api;
					offset += sizeof(SIZE_T);
				}
			}
			else
			{
				free(reinterpret_cast<HINSTANCE>(base));
				return nullptr;
			}
			++import_descriptor;
		}

		reloc_item = reinterpret_cast<IMAGE_BASE_RELOCATION*>(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + base);
		while(reloc_item->SizeOfBlock)//relocation item size
		{
			reloc_number = (reloc_item->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);//relocation item number
			reloc_entry = reinterpret_cast<LPWORD>(reloc_item + 1);//base address of relocation
			while(reloc_number--)
			{
				if(*reloc_entry)
				{
					reloc_address = reloc_item->VirtualAddress + (*reloc_entry & 0x0FFF);//calculate the virtual address of relocation
					size_t virtual_address = *reinterpret_cast<PSIZE_T>(&base[reloc_address]);
					*reinterpret_cast<PSIZE_T>(&base[reloc_address]) = virtual_address + size_t(base) - nt_header->OptionalHeader.ImageBase;
				}
				++reloc_entry;
			}
			reloc_item = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<LPBYTE>(reloc_item) + reloc_item->SizeOfBlock);
		}

		entry_point = base + nt_header->OptionalHeader.AddressOfEntryPoint;
		auto section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt_header + 1);
		for(auto section_index = 0; section_index < nt_header->FileHeader.NumberOfSections; ++section_index)
		{
			if(section_header[section_index].VirtualAddress + base <= entry_point &&
				section_header[section_index].VirtualAddress + base + section_header[section_index].SizeOfRawData > entry_point)
			{
				VirtualProtect(base + section_header[section_index].VirtualAddress, nt_header->OptionalHeader.SizeOfCode, PAGE_EXECUTE_READ, &offset);
			}
		}
		add_memory_module_to_list(HINSTANCE(base));
		set_moudle_path(HINSTANCE(base), path);
		try{
			main_result = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(entry_point)(HINSTANCE(base), DLL_PROCESS_ATTACH, parameter);
		}
		catch(...)
		{
			main_result = false;
		}
		if(false == main_result)
		{
			free(reinterpret_cast<HINSTANCE>(base));
			base = nullptr;
		}
		return reinterpret_cast<HINSTANCE>(base);
	}
	//Functions like GetProcAddress.
	static void* function_address(HINSTANCE dll, const string& name)
	{
		IMAGE_DOS_HEADER*			dos_header;
		IMAGE_NT_HEADERS*			nt_header;
		IMAGE_SECTION_HEADER*		section_header;
		IMAGE_EXPORT_DIRECTORY*		exports;
		IMAGE_DATA_DIRECTORY*		directory;
		DWORD*						name_ref;
		WORD*						ordinal;
		long						k;
		BYTE*						base;

		base = const_cast<LPBYTE>(reinterpret_cast<const BYTE*>(dll));
		dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
		section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(nt_header + 1);

		directory = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if(0 == directory->Size) return nullptr;

		exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + directory->VirtualAddress);
		if(exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0)
			return nullptr;

		name_ref = reinterpret_cast<DWORD*>(&base[exports->AddressOfNames]);
		ordinal = reinterpret_cast<WORD*>(&base[exports->AddressOfNameOrdinals]);
		for(k = 0; k < (long)exports->NumberOfNames; ++k, ++name_ref, ++ordinal)
			if(reinterpret_cast<const char*>(&base[*name_ref]) == name)
			{
				return base + *reinterpret_cast<DWORD*>(&base[exports->AddressOfFunctions + *ordinal * 4]);
			}
		return nullptr;
	}
	//Free and unregister a dll.
	static void free(HINSTANCE dll)
	{
		IMAGE_DOS_HEADER*			dos_header;
		IMAGE_FILE_HEADER*			file_header;
		IMAGE_OPTIONAL_HEADER*		optional_header;
		IMAGE_SECTION_HEADER*		section_header;
		BYTE*						base;
		LPVOID						entry_point;

		base = const_cast<LPBYTE>(reinterpret_cast<const BYTE*>(dll));
		dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		file_header = reinterpret_cast<IMAGE_FILE_HEADER*>(base + 4 + dos_header->e_lfanew);
		optional_header = reinterpret_cast<IMAGE_OPTIONAL_HEADER*>(file_header + 1);
		section_header = reinterpret_cast<IMAGE_SECTION_HEADER*>(optional_header + 1);

		entry_point = base + optional_header->AddressOfEntryPoint;

		reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(entry_point)(HINSTANCE(base), DLL_PROCESS_DETACH, nullptr);
		remove_memory_module_to_list(dll);
		VirtualFree(dll, 0, MEM_RELEASE);
	}

private:
	static void copy_section(LPBYTE base, LPCVOID source)
	{
		const IMAGE_DOS_HEADER*			dos_header;
		const IMAGE_NT_HEADERS*			nt_header;
		const IMAGE_SECTION_HEADER*		section_header;
		long							section_index;
		LPBYTE							address;
		const BYTE*						section;

		dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(source);
		nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(reinterpret_cast<const BYTE*>(source) + dos_header->e_lfanew);
		section_header = reinterpret_cast<const IMAGE_SECTION_HEADER*>(nt_header + 1);

		for(section_index = 0; section_index < nt_header->FileHeader.NumberOfSections; ++section_index)
		{
			address = base + section_header[section_index].VirtualAddress;
			section = reinterpret_cast<const BYTE*>(source) + section_header[section_index].PointerToRawData;
			memcpy(address, section, section_header[section_index].SizeOfRawData);
		}
	}
};
