#ifndef LEGOUTIL_H
#define LEGOUTIL_H

#include <windows.h>

#include "extra.h"
#include "mxmatrix.h"

#define NORMVEC3(dst, src) { \
	MxDouble len = sqrt(NORMSQRD3(src)); \
	VDS3(dst, src, len); }

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

template <class T>
inline void GetScalar(char **p_source, T& p_dest)
{
  p_dest = *(T*) *p_source;
  *p_source += sizeof(T);
}

template <class T>
inline T GetScalar(T **p_source)
{
  T val = **p_source;
  *p_source += 1;
  return val;
}

template <class T>
inline void GetDouble(char **p_source, T& p_dest)
{
  p_dest = *(double*) *p_source;
  *p_source += sizeof(double);
}

template <class T>
inline void GetString(char **p_source, const char *&p_dest, T *p_obj, void (T::*p_setter)(const char*))
{
  (p_obj->*p_setter)(*p_source);
  *p_source += strlen(p_dest) + 1;
}

ExtraActionType MatchActionString(const char *);
void ConvertHSVToRGB(float r, float g, float b, float* out_r, float* out_g, float* out_b);
void SetAppCursor(WPARAM p_wparam);
void CalcLocalTransform(const MxVector3 &p_posVec, const MxVector3 &p_dirVec,
                        const MxVector3 &p_upVec, MxMatrix &p_outMatrix);

#endif // LEGOUTIL_H
