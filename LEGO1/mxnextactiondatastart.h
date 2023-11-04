#ifndef MXNEXTACTIONDATASTART_H
#define MXNEXTACTIONDATASTART_H

#include "mxcore.h"

// VTABLE 0x100dc9a0
class MxNextActionDataStart : public MxCore {
public:
    // OFFSET: LEGO1 0x100c1900
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x101025a0
		return "MxNextActionDataStart";
	}

	// OFFSET: LEGO1 0x100c1910
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxNextActionDataStart::ClassName()) || MxCore::IsA(name);
	}
};

#endif // MXNEXTACTIONDATASTART_H
