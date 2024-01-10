#include "mxstring.h"

#include "decomp.h"

#include <stdlib.h>
#include <string.h>

DECOMP_SIZE_ASSERT(MxString, 0x10)

// FUNCTION: LEGO1 0x100ae200
MxString::MxString()
{
	// Set string to one char in length and set that char to null terminator
	this->m_data = new char[1];
	this->m_data[0] = 0;
	this->m_length = 0;
}

// FUNCTION: LEGO1 0x100ae2a0
MxString::MxString(const MxString& p_str)
{
	this->m_length = p_str.m_length;
	this->m_data = new char[this->m_length + 1];
	strcpy(this->m_data, p_str.m_data);
}

// FUNCTION: LEGO1 0x100ae350
MxString::MxString(const char* p_str)
{
	if (p_str) {
		this->m_length = strlen(p_str);
		this->m_data = new char[this->m_length + 1];
		strcpy(this->m_data, p_str);
	}
	else {
		this->m_data = new char[1];
		this->m_data[0] = 0;
		this->m_length = 0;
	}
}

// FUNCTION: LEGO1 0x100ae420
MxString::~MxString()
{
	delete[] this->m_data;
}

// FUNCTION: LEGO1 0x100ae490
void MxString::ToUpperCase()
{
	strupr(this->m_data);
}

// FUNCTION: LEGO1 0x100ae4a0
void MxString::ToLowerCase()
{
	strlwr(this->m_data);
}

// FUNCTION: LEGO1 0x100ae4b0
MxString& MxString::operator=(const MxString& p_str)
{
	if (this->m_data != p_str.m_data) {
		delete[] this->m_data;
		this->m_length = p_str.m_length;
		this->m_data = new char[this->m_length + 1];
		strcpy(this->m_data, p_str.m_data);
	}

	return *this;
}

// FUNCTION: LEGO1 0x100ae510
const MxString& MxString::operator=(const char* p_data)
{
	if (this->m_data != p_data) {
		delete[] this->m_data;
		this->m_length = strlen(p_data);
		this->m_data = new char[this->m_length + 1];
		strcpy(this->m_data, p_data);
	}

	return *this;
}

// Return type is intentionally just MxString, not MxString&.
// This forces MSVC to add $ReturnUdt$ to the stack for 100% match.
// FUNCTION: LEGO1 0x100ae580
MxString MxString::operator+(const char* p_str)
{
	// MxString constructor allocates 1 byte for m_data, so free that first
	MxString tmp;
	delete[] tmp.m_data;

	tmp.m_length = strlen(p_str) + this->m_length;
	tmp.m_data = new char[tmp.m_length + 1];

	strcpy(tmp.m_data, this->m_data);
	strcpy(tmp.m_data + this->m_length, p_str);

	return MxString(tmp);
}

// FUNCTION: LEGO1 0x100ae690
MxString& MxString::operator+=(const char* p_str)
{
	int newlen = this->m_length + strlen(p_str);

	char* tmp = new char[newlen + 1];
	strcpy(tmp, this->m_data);
	strcpy(tmp + this->m_length, p_str);

	delete[] this->m_data;
	this->m_length = newlen;
	this->m_data = tmp;

	return *this;
}
