#ifndef MXSTRING_H
#define MXSTRING_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc110
// VTABLE: BETA10 0x101c1be0
// SIZE 0x10
class MxString : public MxCore {
public:
	MxString(const MxString& p_str);
	~MxString() override;
	const MxString& operator=(const char* p_data);

	MxString();
	MxString(const char*);
	MxString(const char*, MxU16);
	void Reverse();
	void ToUpperCase();
	void ToLowerCase();
	MxString& operator=(const MxString& p_str);
	MxString operator+(const MxString& p_str);
	MxString operator+(const char* p_str);
	MxString& operator+=(const char* p_str);

	static void CharSwap(char* p_a, char* p_b);

	// FUNCTION: BETA10 0x10017c50
	inline char* GetData() const { return m_data; }

	// FUNCTION: BETA10 0x10067630
	inline const MxU16 GetLength() const { return m_length; }

	// FUNCTION: BETA10 0x100d8a30
	inline MxBool Equal(const MxString& p_str) const { return strcmp(m_data, p_str.m_data) == 0; }

	// FUNCTION: BETA10 0x1012a810
	inline MxS8 Compare(const MxString& p_str) const { return strcmp(m_data, p_str.m_data); }

	// SYNTHETIC: LEGO1 0x100ae280
	// SYNTHETIC: BETA10 0x1012c9d0
	// MxString::`scalar deleting destructor'

private:
	char* m_data;   // 0x08
	MxU16 m_length; // 0x0c
};

#endif // MXSTRING_H
