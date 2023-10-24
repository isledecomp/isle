#include "mxvariable.h"

#include "decomp.h"
#include "mxstring.h"

DECOMP_SIZE_ASSERT(MxVariable, 0x24)

// OFFSET: LEGO1 0x1003bea0
MxString* MxVariable::GetValue()
{
	return &m_value;
}

// OFFSET: LEGO1 0x1003beb0
void MxVariable::SetValue(const char* value)
{
	m_value = value;
}

// OFFSET: LEGO1 0x1003bec0
void MxVariable::Destroy()
{
	delete this;
}
