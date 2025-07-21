#ifndef MXVARIABLE_H
#define MXVARIABLE_H

#include "mxcore.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d7498
// VTABLE: BETA10 0x101bc038
// SIZE 0x24
class MxVariable {
public:
	// FUNCTION: BETA10 0x1007b750
	MxVariable() {}

	// FUNCTION: BETA10 0x1012a840
	MxVariable(const char* p_key, const char* p_value)
	{
		m_key = p_key;
		m_key.ToUpperCase();
		m_value = p_value;
	}

	// FUNCTION: BETA10 0x1012aa30
	MxVariable(const char* p_key)
	{
		m_key = p_key;
		m_key.ToUpperCase();
	}

	// FUNCTION: LEGO1 0x1003bea0
	// FUNCTION: BETA10 0x1007b810
	virtual MxString* GetValue() { return &m_value; } // vtable+0x00

	// FUNCTION: LEGO1 0x1003beb0
	// FUNCTION: BETA10 0x1007b840
	virtual void SetValue(const char* p_value) { m_value = p_value; } // vtable+0x04

	// FUNCTION: LEGO1 0x1003bec0
	// FUNCTION: BETA10 0x1007b870
	virtual void Destroy() { delete this; } // vtable+0x08

	// FUNCTION: BETA10 0x1012a7f0
	const MxString* GetKey() const { return &m_key; }

	// SYNTHETIC: BETA10 0x1007b8c0
	// MxVariable::`scalar deleting destructor'

protected:
	MxString m_key;   // 0x04
	MxString m_value; // 0x14
};

// SYNTHETIC: LEGO1 0x1003bf40
// SYNTHETIC: BETA10 0x1007b910
// MxVariable::~MxVariable

#endif // MXVARIABLE_H
