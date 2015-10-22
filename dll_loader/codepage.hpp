/*
	Author: Easton
	Date:	2013-02-27

	This library encapsulates MultiByteToWideChar and WideCharToMultiByte into more convenient function, offering transformation between arbitrary encoding and unicode.
*/
#pragma once
#include <Windows.h>
#include <string>
class codepage
{
public:
	//The utf8 and unicode transforming group.
	static std::wstring utf8_to_unicode(const std::string& utf8) {return _to_unicode<CP_UTF8>(utf8);}
	static std::string unicode_to_utf8(const std::wstring& unicode) {return _unicode_to<CP_UTF8>(unicode);}

	//The ASCII and unicode transforming group
	static std::wstring acp_to_unicode(const std::string& text) {return _to_unicode<CP_ACP>(text);}
	static std::string unicode_to_acp(const std::wstring& unicode) {return _unicode_to<CP_ACP>(unicode);}

	//The generic transforming group.
	template<unsigned long CodePage>
	static std::wstring _to_unicode(const std::string& text)
	{
		if(text.empty()) return L"";
		size_t length = MultiByteToWideChar(CodePage, 0, text.c_str(), (int)text.size(), nullptr, 0);
		std::wstring unicode(length, L'C');
		MultiByteToWideChar(CodePage, 0, text.c_str(), (int)text.size(), &*unicode.begin(), (int)length);
		return unicode;
	}
	template<unsigned long CodePage>
	static std::wstring _to_unicode(const std::wstring& text) {return text;}
	template<unsigned long CodePage>
	static std::string _unicode_to(const std::wstring& unicode)
	{
		if(unicode.empty()) return "";
		size_t length = WideCharToMultiByte(CodePage, 0, unicode.c_str(), (int)unicode.length(), nullptr, 0, nullptr, nullptr);
		std::string text(length, 'C');
		WideCharToMultiByte(CodePage, 0, unicode.c_str(), (int)unicode.length(), &*text.begin(), (int)length, nullptr, nullptr);
		return text;
	}
	template<unsigned long CodePage>
	static std::string _unicode_to(const std::string& unicode) {return unicode;}
};