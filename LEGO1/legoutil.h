#ifndef LEGOUTIL_H
#define LEGOUTIL_H

template <class T>
inline T Abs(T p_t)
{
  return p_t < 0 ? -p_t : p_t;
}

#endif // LEGOUTIL_H
