#include "mxstringvariable.h"
#include "mxstring.h"


// OFFSET: LEGO1 0x1003bea0
MxString *MxStringVariable::GetString()
{
  return &m_string;
}

// OFFSET: LEGO1 0x1003beb0
void MxStringVariable::SetString(const char *colorString)
{
  m_string = colorString;
}

//FIXME: Figure out what exactly this class is used for. It is used in LegoGameState::LegoGameState when loading the background color, and for loading the "fsmovie" variable
// OFFSET: LEGO1 0x1003bec0
void MxStringVariable::Destroy()
{
  delete this;
}
