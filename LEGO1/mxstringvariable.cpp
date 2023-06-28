#include "MxStringVariable.h"
#include "mxstring.h"

// OFFSET: LEGO1 0x1003bec0
MxStringVariable::~MxStringVariable()
{

  delete &m_colorString;
  delete &m_name;
}

// OFFSET: LEGO1 0x1003bea0
MxString *MxStringVariable::GetColorString()
{
  return &m_colorString;
}

// OFFSET: LEGO1 0x1003beb0
void MxStringVariable::SetColorString(const char *colorString)
{
  m_colorString = colorString;
}
