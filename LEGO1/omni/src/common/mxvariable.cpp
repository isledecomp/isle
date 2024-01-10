#include "mxvariable.h"

#include "decomp.h"
#include "mxstring.h"

DECOMP_SIZE_ASSERT(MxVariable, 0x24)

// FUNCTION: LEGO1 0x1003bea0
MxString* MxVariable::GetValue()
{
	return &m_value;
}

// FUNCTION: LEGO1 0x1003beb0
void MxVariable::SetValue(const char* p_value)
{
	m_value = p_value;
}

// FUNCTION: LEGO1 0x1003bec0
void MxVariable::Destroy()
{
	delete this;
}
