#include "legobackgroundcolor.h"
#include "legoomni.h"
#include "legoutil.h"

// OFFSET: LEGO1 0x1003bfb0
LegoBackgroundColor::LegoBackgroundColor(const char* name, const char* colorString)
{
  this->m_name.operator=(name);
  this->m_name.ToUpperCase();
  SetColorString(colorString);
}



void LegoBackgroundColor::SetColorString(const char* colorString)
{

}