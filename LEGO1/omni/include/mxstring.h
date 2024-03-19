#ifndef MXSTRING_H
#define MXSTRING_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc110
// SIZE 0x10
class MxString : public MxCore {
public:
	MxString(const MxString& p_str);
	~MxString() override;
	const MxString& operator=(const char* p_data);

	MxString();
	MxString(const char*);
	void ToUpperCase();
	void ToLowerCase();
	MxString& operator=(const MxString& p_str);
	MxString operator+(const char* p_str);
	MxString& operator+=(const char* p_str);

	inline MxS8 Compare(const MxString& p_str) const { return strcmp(m_data, p_str.m_data); }
	inline const char* GetData() const { return m_data; }
	inline char* GetDataPtr() const { return m_data; }
	inline const MxU16 GetLength() const { return m_length; }

	// SYNTHETIC: LEGO1 0x100ae280
	// MxString::`scalar deleting destructor'

private:
	char* m_data;   // 0x08
	MxU16 m_length; // 0x0c
};

#endif // MXSTRING_H
