#ifndef MXRECT32_H
#define MXRECT32_H

#define MxRect32GetWidth(rect) (rect.m_right - rect.m_left) + 1
#define MxRect32GetHeight(rect) (rect.m_bottom - rect.m_top) + 1

class MxRect32
{
public:
  MxRect32() { }
  MxRect32(MxS32 p_left, MxS32 p_top, MxS32 p_right, MxS32 p_bottom)
  {
    this->m_left = p_left;
    this->m_top = p_top;
    this->m_right = p_right;
    this->m_bottom = p_bottom;
  }

  MxS32 m_left;
  MxS32 m_top;
  MxS32 m_right;
  MxS32 m_bottom;
};

#endif // MXRECT32_H
