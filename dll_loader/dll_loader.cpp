// dll_loader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "memory_library.hpp"

int main()
{
	memory_library::load_from_file(L"test_dll.dll");
    return 0;
}

