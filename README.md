There are some cases you may want to load a library from encrypted file, or download a plugin from network and load it without saving to local .dll file. This library allows you to load a windows dynamic library from memory.

  void memory_library.load(const vector<char>& buffer);

The library supports exception handling inside memory loaded DLLs. So far Windows 8.1 or ealier version of Windows are supported. Including x86 and x64.
