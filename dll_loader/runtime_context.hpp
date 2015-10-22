/*
	Author: Easton
	Data:	2013-02-27

	This library covers three commonest runtime entitys, they are thread, module and process.
	Note that the concept runtime entity isn't the normal sense of entity, the easier way to explain the scenario is, if you want to access the context bound to one of these entity,
	you would access the corresponding context preceeded by EntityType::, where EntityType is one of these runtime entity. So all method of these classes are all static.
	THe major usages of the scenario is to entitle developers to access arbitrary type of value which is named by a key and bound to the designed context. Such as:

		runtime_context::process::set_value(L"KeyOfValue", Type value);

	Latter you would probably get the value by calling:

		Type value = runtime_context::process::get_value<Type>(L"KeyOfValue");

	Where Type is arbitrary, but it's strongly recommended that DO NOT use raw pointer as a value, since the semantic content of a pointer is what it points to, not itself.
	If you do need to keep a pointer, please use smart pointer, the best and most convenient way is using shared_ptr to encapsulate the pointer. The runtime entity goes further,
	if you want to get or create (if not exists) a smart pointer of certain type, you can call EntityType::create_or_get_ptr<Type>(L"KeyOfValue"), which returns a shared_ptr<Type>.
	The function guarantees that the accesing value will be automatically created if it does not exist yet. And otherwise does the same way as EntityType::get_value<shared_ptr<Type>>(L"KeyOfValue").
	
	As there literal meaning, each runtime entity is described:
	thread:	ensures the accessed values be released when the thread exits.
	module: ensures the accessed values be released when the module is about to be unloaded.
	process: ensures the accessed values be released when the process is about to quit.

	//The following snippet illustrates how to schedule the handle to be closed on exiting the thread.
	//The underlying CloseHandle will be called with each handle added by close_handle_on_existing passed to it.

		HANDLE event = CreateMutex(nullptr, true, L"test_mutex")
		EntityType::close_handle_on_existing(event);

	//queue_exit_operation is designed for the more generic work which can't be achieved through the above methods.

		EntityType::queue_exit_operation(
				[]()
				{
					//Note that the exiting operations are always called preceding any named values.
					TerminateProcess(any_cast<HANDLE>(threading::value(L"test_process")), 0);
				}
			);

	CAUTION: 1. The value managed by process will be automatically released when the module which accesses process-width value at the first time.
				The best practice is access any process value in the EXE proceeding any other DLLs.
			 2.	The values bound to the thread will not be released if the thread is terminated by TerminateThread.
				The reasonable practice is the let the thread core routine exit itself.
*/

#pragma once
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>
#include <functional>
#include <custom/usefultypes.hpp>
#include <custom/exceptions.hpp>
#include <boost/serialization/singleton.hpp>
#include <list>
#include <set>
#include <map>
#include <windows.h>
#include <tchar.h>

using namespace std;

namespace runtime_context
{
	//The handy macro to define a critical section. Note that the section object is not necessarily be which defined in the current process context, if a key other than empty string is passed in.
	#define	ProcessCriticalSection	custom::lock_guard<boost::recursive_mutex> a7031x_context_lock_guard##__LINE__ = runtime_context::process::critical_section_imply
	#define	ProcessSharedSection(key)	boost::shared_lock<boost::shared_mutex> a7031x_context_shared_lock_guard(*runtime_context::process::create_or_get_ptr<boost::shared_mutex>(key))
	#define	ProcessUniqueSection(key)	boost::unique_lock<boost::shared_mutex> a7031x_context_shared_lock_guard(*runtime_context::process::create_or_get_ptr<boost::shared_mutex>(key))
	template<typename EntityType, typename MutexType = boost::recursive_mutex>
	class runtime_instance
	{
	#define	DeclareContext(context)\
			auto& context = EntityType::get_context();\
			boost::lock_guard<MutexType> a7031x_lock_guard_entity(context.section);
	protected:
		class context_imply : boost::noncopyable
		{
		public:
			typedef std::map<wstring, boost::any, custom::iless>	value_map;
			value_map				values;
			list<function<void()>>	exit_functions;
			set<HANDLE>				handles;
			MutexType				section;

			//The destructor does three things inside it.
			//1 Calls each finalizing functions (saved in exit_functions variable).
			//2 Release all registered handles.
			//3 Release all value held by values, this is the natural work of being a destructor.
			~context_imply()
			{
				for_each(exit_functions.begin(), exit_functions.end(), [](std::function<void()> f) {f();});
				for_each(handles.begin(), handles.end(), CloseHandle);
			}
		};
	public:
		//Access named value bound to the current thread. It's recommended to use DeclareCriticalSection instead.
		static boost::recursive_mutex& critical_section_imply(const wstring& name)
		{
			DeclareContext(context);
			return *create_or_get_ptr<boost::recursive_mutex>(L"mutex:" + name);
		}
		template<typename ValueType>
		static ValueType get_value(const wstring& key)
		{
			DeclareContext(context);
			auto it = context.values.find(key);
			if(context.values.end() == it) commit_error(L"cannot find the value named " + key);
			return boost::any_cast<ValueType>(it->second);
		}
		template<typename ValueType>
		static ValueType get_value_with_default(const wstring& key, const ValueType& def = ValueType())
		{
			DeclareContext(context);
			auto it = context.values.find(key);
			if(context.values.end() == it)
				return def;
			else
				return boost::any_cast<ValueType>(it->second);
		}
		template<class ClassType>
		static std::shared_ptr<ClassType> create_or_get_ptr(const wstring& key)
		{
			DeclareContext(context);
			if(false == exists(key))
				set_value(key, std::make_shared<ClassType>());
			return get_value<std::shared_ptr<ClassType>>(key);
		}
		static void set_value(const wstring& key, const boost::any& value)
		{
			DeclareContext(context);
			context.values[key] = value;
		}
		static void erase(const wstring& key)
		{
			DeclareContext(context);
			context.values.erase(key);
		}
		static bool exists(const wstring& key)
		{
			DeclareContext(context);
			auto it = context.values.find(key);
			if(context.values.end() == it) return false;
			return false == it->second.empty();
		}
		//Schedule void(*)() typed operation to be called when current thread exiting.
		static void queue_exit_operation(std::function<void()> f)
		{
			DeclareContext(context);
			context.exit_functions.push_back(f);
		}
		//Schedule a handle to be close via CloseHandle when current thread exiting.
		static void close_handle_on_exiting(HANDLE handle)
		{
			DeclareContext(context);
			context.handles.insert(handle);
		}
		static void cancel_handle_on_exiting(HANDLE handle)
		{
			DeclareContext(context);
			context.handles.erase(handle);
		}
		#undef	DeclareContext
	};

	class nullmutex
	{
	public:
		void lock() {}
		void unlock() {}
	};

	class process : public runtime_instance<process>
	{
	public:
		static context_imply& get_context()
		{
			//For performance reason, use p_context to cache to environment value.
			//Define the environment value to hold the address of the context in text form, since the environment value can only be text.
			wchar_t env[64];
			wstring key = L"0629FEF3-0E3D-4F7A-AA96-DF54960F7834:";	//The context guid, in order to distinguish with other keys.
			key += boost::lexical_cast<wstring, uint32_t>(GetCurrentProcessId());
			if(GetEnvironmentVariableW(key.c_str(), env, _countof(env)))
			{
				//If SetEnvironmentVariable has been called, this branch must be achieved.
				//Then decode the context from env string.
			//	p_context = (context_imply*)_wtoi64(env);
			//	return *p_context;
				return *(context_imply*)_wtoi64(env);
			}
			else
			{
				auto header = reinterpret_cast<IMAGE_DOS_HEADER*>(GetModuleHandleW(nullptr));
				context_imply*& address = *reinterpret_cast<context_imply**>(&header->e_res2[0]);
				if(nullptr == address)
				{
					DWORD oldProtect;
					VirtualProtect(header, sizeof(header), PAGE_READWRITE, &oldProtect);
					address = &boost::serialization::singleton<context_imply>::get_mutable_instance();

					queue_exit_operation([key, header]()
					{
						SetEnvironmentVariableW(key.c_str(), nullptr);
						*reinterpret_cast<context_imply**>(&header->e_res2[0]) = nullptr;
					});
				}
				_i64tow_s((size_t)address, env, _countof(env), 10);
				SetEnvironmentVariableW(key.c_str(), env);
				return *address;
			}
			//Define the local static context to hold the process context, which is immediately registered to the environment value.
			//static context_imply s_context;
		//	auto pp_context = &p_context;
			//Technically this scenario is not perfectly thread safe for the first time call.
			//Consider the extreme situation that two threads in different modules happened to call or indirectly call get_context when the context hasn't been created yet,
			//in this case two s_context will be created. But it doesn't even matter, the only effect is an extra s_context which will never be used, and both will be released when
			//the module being released or the process exiting. The only situation that matter is at least another one thread accessed the process context between the two
			//SetEnvironmentVariable callings. This situation is just almost impossible to happen except intended.
		}
	};

	class thread : public runtime_instance<thread, nullmutex>
	{
	public:
		static context_imply& get_context()
		{
			//Use the thread_specific_ptr smart pointer to retain the thread context, which uses thread local storage(TLS) implicitly.
			static boost::thread_specific_ptr<context_imply> context_ptr;
			if(nullptr == context_ptr.get())
			{
				wchar_t key[64];
				_i64tow_s(0x8c53b9d64a72f39e + GetCurrentThreadId(), key, _countof(key), 16);
				if(process::exists(key))
				{
					auto context = process::get_value<context_imply*>(key);
			//		context_ptr.reset(context);
					return *context;
				}
				context_ptr.reset(new context_imply);
				process::set_value(key, context_ptr.get());
				std::wstring skey = key;
				queue_exit_operation([skey]()
									{
										__try{
											process::erase(skey);
										}
										__except(EXCEPTION_EXECUTE_HANDLER)
										{

										}
									});
			}
			return *context_ptr.get();
		}
		//Access named value bound to the current thread.
		template<typename ValueType>
		static ValueType& value(const wstring& key)
		{
			auto& v = get_context().values[key];
			return *boost::any_cast<ValueType>(&v);
		}
		static boost::any& value(const wstring& key)
		{
			return get_context().values[key];
		}
	};

	//The most simple context, retained by each module.
	class module : public runtime_instance<module>
	{
	public:
		static context_imply& get_context()
		{
			static context_imply context;
			return context;
		}
	};
};