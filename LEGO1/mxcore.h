#ifndef MXCORE_H
#define MXCORE_H

#include "compat.h"
#include "mxtypes.h"

#include <string.h>

class MxParam;

// TODO: Find proper compilation unit to put these
// OFFSET: LEGO1 0x100140d0 TEMPLATE
// MxCore::IsA

// OFFSET: LEGO1 0x100144c0 TEMPLATE
// MxCore::ClassName

// VTABLE 0x100dc0f8
// SIZE 0x8
class MxCore {
public:
	__declspec(dllexport) MxCore();
	__declspec(dllexport) virtual ~MxCore();                 // vtable+00
	__declspec(dllexport) virtual MxLong Notify(MxParam& p); // vtable+04
	virtual MxResult Tickle();                               // vtable+08

	inline virtual const char* ClassName() const // vtable+0c
	{
		// 0x100f007c
		return "MxCore";
	}

	inline virtual MxBool IsA(const char* name) const // vtable+10
	{
		return !strcmp(name, MxCore::ClassName());
	}

	inline MxU32 GetId() { return m_id; }

private:
	MxU32 m_id;
};

#endif // MXCORE_H
