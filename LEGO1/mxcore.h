#ifndef MXCORE_H
#define MXCORE_H

#include "compat.h"
#include "mxtypes.h"

#include <string.h>

class MxParam;

// VTABLEADDR 0x100dc0f8
// SIZE 0x8
class MxCore {
public:
	__declspec(dllexport) MxCore();

	// VTABLE 0x0
	__declspec(dllexport) virtual ~MxCore();

	// VTABLE 0x4
	__declspec(dllexport) virtual MxResult Notify(MxParam& p);

	// VTABLE 0x8
	virtual MxResult Tickle();

	// OFFSET: LEGO1 0x100144c0
	inline virtual const char* ClassName() const // vtable+0c
	{
		// 0x100f007c
		return "MxCore";
	}

	// OFFSET: LEGO1 0x100140d0
	inline virtual MxBool IsA(const char* name) const // vtable+10
	{
		return !strcmp(name, MxCore::ClassName());
	}

	inline MxU32 GetId() { return m_id; }

private:
	MxU32 m_id;
};

#endif // MXCORE_H
