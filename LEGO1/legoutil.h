#ifndef LEGOUTIL_H
#define LEGOUTIL_H

template <class T>
inline T Abs(T p_t)
{
  return p_t < 0 ? -p_t : p_t;
}

template <class T>
inline T Min(T p_t1, T p_t2)
{
  return p_t1 < p_t2 ? p_t1 : p_t2;
}

template <class T>
inline T Max(T p_t1, T p_t2)
{
  return p_t1 > p_t2 ? p_t1 : p_t2;
}

#endif // LEGOUTIL_H
