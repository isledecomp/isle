#include "mxbackgroundcolor.h"
#include "mxstring.h"


// OFFSET: LEGO1 0x1003bea0
MxString* MxBackgroundColor::GetColorString()
{
  return &m_colorString;
}

// OFFSET: LEGO1 0x1003beb0
void MxBackgroundColor::SetColorString(const char* colorString)
{
   this->m_colorString.operator=(colorString);
}
