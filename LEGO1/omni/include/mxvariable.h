#ifndef MXVARIABLE_H
#define MXVARIABLE_H

#include "mxcore.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d7498
// SIZE 0x24
class MxVariable {
public:
	MxVariable() {}
	MxVariable(const char* p_key)
	{
		m_key = p_key;
		m_key.ToUpperCase();
	}
	MxVariable(const char* p_key, const char* p_value)
	{
		m_key = p_key;
		m_key.ToUpperCase();
		m_value = p_value;
	}

	// FUNCTION: LEGO1 0x1003bea0
	virtual MxString* GetValue() { return &m_value; } // vtable+0x00

	// FUNCTION: LEGO1 0x1003beb0
	virtual void SetValue(const char* p_value) { m_value = p_value; } // vtable+0x04

	// FUNCTION: LEGO1 0x1003bec0
	virtual void Destroy() { delete this; } // vtable+0x08

	inline const MxString* GetKey() const { return &m_key; }

protected:
	MxString m_key;   // 0x04
	MxString m_value; // 0x14
};

// SYNTHETIC: LEGO1 0x1003bf40
// MxVariable::~MxVariable

#endif // MXVARIABLE_H
