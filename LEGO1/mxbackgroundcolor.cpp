#include "mxbackgroundcolor.h"
#include "mxstring.h"

// OFFSET: LEGO1 0x1003bec0
MxBackgroundColor::~MxBackgroundColor()
{

  delete &m_colorString;
  delete &m_name;
}

// OFFSET: LEGO1 0x1003bea0
MxString *MxBackgroundColor::GetColorString()
{
  return &m_colorString;
}

// OFFSET: LEGO1 0x1003beb0
void MxBackgroundColor::SetColorString(const char *colorString)
{
  m_colorString.operator=(colorString);
}
