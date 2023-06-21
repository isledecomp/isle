#ifndef MXRECT32_H
#define MXRECT32_H

class MxRect32
{
public:
  MxRect32() { }
  MxRect32(int p_left, int p_top, int p_right, int p_bottom)
  {
    this->m_left = p_left;
    this->m_top = p_top;
    this->m_right = p_right;
    this->m_bottom = p_bottom;
  }

  int m_left;
  int m_top;
  int m_right;
  int m_bottom;
};

#endif // MXRECT32_H
