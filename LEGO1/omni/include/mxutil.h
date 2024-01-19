#ifndef MXUTIL_H
#define MXUTIL_H

#include "mxtypes.h"

#include <string.h>

class MxDSFile;
class MxDSObject;
class MxDSAction;

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
inline void GetScalar(MxU8** p_source, T& p_dest)
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
inline void GetDouble(MxU8** p_source, T& p_dest)
{
	p_dest = *(double*) *p_source;
	*p_source += sizeof(double);
}

template <class T>
inline void GetString(MxU8** p_source, char** p_dest, T* p_obj, void (T::*p_setter)(const char*))
{
	(p_obj->*p_setter)((char*) *p_source);
	*p_source += strlen(*p_dest) + 1;
}

MxBool GetRectIntersection(
	MxS32 p_rect1Width,
	MxS32 p_rect1Height,
	MxS32 p_rect2Width,
	MxS32 p_rect2Height,
	MxS32* p_rect1Left,
	MxS32* p_rect1Top,
	MxS32* p_rect2Left,
	MxS32* p_rect2Top,
	MxS32* p_width,
	MxS32* p_height
);

__declspec(dllexport) void MakeSourceName(char*, const char*);
__declspec(dllexport) void SetOmniUserMessage(void (*)(const char*, int));
void FUN_100b7220(MxDSAction* p_action, MxU32 p_newFlags, MxBool p_setFlags);
__declspec(dllexport) MxDSObject* CreateStreamObject(MxDSFile*, MxS16);

MxBool KeyValueStringParse(char*, const char*, const char*);

#endif // MXUTIL_H
