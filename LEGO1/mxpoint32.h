#ifndef MXPOINT32_H
#define MXPOINT32_H

#include "mxtypes.h"

class MxPoint32
{
public:
  MxPoint32() { }
  MxPoint32(MxS32 x, MxS32 y)
  {
    this->m_x = x;
    this->m_y = y;
  }

  MxS32 m_x;
  MxS32 m_y;
};

#endif // MXPOINT32_H
