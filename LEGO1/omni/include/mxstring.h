#ifndef MXSTRING_H
#define MXSTRING_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100dc110
// VTABLE: BETA10 0x101c1be0
// SIZE 0x10
class MxString : public MxCore {
public:
	MxString();
	MxString(const MxString& p_str);
	MxString(const char* p_str);
	MxString(const char* p_str, MxU16 p_maxlen);
	~MxString() override;

	void Reverse();
	void ToUpperCase();
	void ToLowerCase();

	MxString& operator=(const MxString& p_str);
	const MxString& operator=(const char* p_str);
	MxString operator+(const MxString& p_str) const;
	MxString operator+(const char* p_str) const;
	MxString& operator+=(const char* p_str);

	static void CharSwap(char* p_a, char* p_b);

	// FUNCTION: BETA10 0x10017c50
	char* GetData() const { return m_data; }

	// FUNCTION: BETA10 0x10067630
	const MxU16 GetLength() const { return m_length; }

	// FUNCTION: BETA10 0x100d8a30
	MxBool Equal(const MxString& p_str) const { return strcmp(m_data, p_str.m_data) == 0; }

	// FUNCTION: BETA10 0x1012a810
	MxS8 Compare(const MxString& p_str) const { return strcmp(m_data, p_str.m_data); }

	// SYNTHETIC: LEGO1 0x100ae280
	// SYNTHETIC: BETA10 0x1012c9d0
	// MxString::`scalar deleting destructor'

private:
	char* m_data;   // 0x08
	MxU16 m_length; // 0x0c
};

#endif // MXSTRING_H
