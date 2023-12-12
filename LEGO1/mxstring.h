#ifndef MXSTRING_H
#define MXSTRING_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc110
class MxString : public MxCore {
public:
	__declspec(dllexport) MxString(const MxString& p_str);
	__declspec(dllexport) virtual ~MxString();
	__declspec(dllexport) const MxString& operator=(const char* p_data);

	MxString();
	MxString(const char*);
	void ToUpperCase();
	void ToLowerCase();
	MxString& operator=(const MxString& p_str);
	MxString operator+(const char* p_str);
	MxString& operator+=(const char* p_str);

	inline MxS8 Compare(const MxString& p_str) const { return strcmp(m_data, p_str.m_data); }
	inline const char* GetData() const { return m_data; }

private:
	char* m_data;
	MxU16 m_length;
};

#endif // MXSTRING_H
