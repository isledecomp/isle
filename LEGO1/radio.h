#ifndef RADIO_H
#define RADIO_H

#include "mxcore.h"

// VTABLE: LEGO1 0x100d6d10
class Radio : public MxCore {
public:
	virtual ~Radio() override;

	// FUNCTION: LEGO1 0x1002c8e0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f328c
		return "Radio";
	}

	// FUNCTION: LEGO1 0x1002c8f0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Radio::ClassName()) || MxCore::IsA(name);
	}
};

#endif // RADIO_H
