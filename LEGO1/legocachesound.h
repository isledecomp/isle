#ifndef LEGOCACHESOUND_H
#define LEGOCACHESOUND_H

#include "mxcore.h"

// VTABLEADDR 0x100d4718
// SIZE 0x88
class LegoCacheSound : public MxCore {
public:
	LegoCacheSound();
	virtual ~LegoCacheSound() override; // vtable+0x0

	// OFFSET: LEGO1 0x10006580
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// 0x100f01c4
		return "LegoCacheSound";
	}

	// OFFSET: LEGO1 0x10006590
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, LegoCacheSound::ClassName()) || MxCore::IsA(name);
	}

private:
	void Init();
};

#endif // LEGOCACHESOUND_H
