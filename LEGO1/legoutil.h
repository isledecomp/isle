#ifndef LEGOUTIL_H
#define LEGOUTIL_H

#include "extra.h"
#include "legoentity.h"
#include "mxatomid.h"
#include "mxtypes.h"

#include <windows.h>

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
inline void GetScalar(char** p_source, T& p_dest)
{
	p_dest = *(T*) *p_source;
	*p_source += sizeof(T);
}

template <class T>
inline T GetScalar(T** p_source)
{
	T val = **p_source;
	*p_source += 1;
	return val;
}

template <class T>
inline void GetDouble(char** p_source, T& p_dest)
{
	p_dest = *(double*) *p_source;
	*p_source += sizeof(double);
}

template <class T>
inline void GetString(char** p_source, const char* p_dest, T* p_obj, void (T::*p_setter)(const char*))
{
	(p_obj->*p_setter)(*p_source);
	*p_source += strlen(p_dest) + 1;
}

ExtraActionType MatchActionString(const char*);
void InvokeAction(ExtraActionType actionId, MxAtomId& pAtom, int targetEntityId, LegoEntity* sender);
void ConvertHSVToRGB(float r, float g, float b, float* out_r, float* out_g, float* out_b);
void FUN_1003ee00(MxAtomId& p_atomId, MxS32 p_id);
void SetAppCursor(WPARAM p_wparam);
MxBool FUN_1003ef60();

#endif // LEGOUTIL_H
