#ifndef LEGOUTIL_H
#define LEGOUTIL_H

#include <windows.h>

#include "extra.h"

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

ExtraActionType MatchActionString(const char *);
void ConvertHSVToRGB(float r, float g, float b, float* out_r, float* out_g, float* out_b);
void SetAppCursor(WPARAM p_wparam);

#endif // LEGOUTIL_H
