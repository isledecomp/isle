#include "mxvideoparamflags.h"

MxVideoParamFlags::MxVideoParamFlags()
{
  // TODO: convert to EnableXXX function calls
  unsigned char bVar1 = this->m_flags1;
  this->m_flags1 = bVar1 & 0xfe;
  this->m_flags1 = bVar1 & 0xfc;
  this->m_flags1 = bVar1 & 0xf8;
  this->m_flags1 = bVar1 & 0xf0;
  this->m_flags1 = bVar1 & 0xe0;
  this->m_flags2 = this->m_flags2 | 2;
  this->m_flags1 = bVar1 & 0xc0;
  this->m_flags1 = bVar1 & 0xc0 | 0x40;
  this->m_flags1 = 0xc0;
}
