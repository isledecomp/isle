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
	virtual MxString* GetValue();
	virtual void SetValue(const char* p_value);
	virtual void Destroy();

	inline const MxString* GetKey() const { return &m_key; }

protected:
	MxString m_key;
	MxString m_value;
};

#endif // MXVARIABLE_H
