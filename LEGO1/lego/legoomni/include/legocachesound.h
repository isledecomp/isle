#ifndef LEGOCACHESOUND_H
#define LEGOCACHESOUND_H

#include "decomp.h"
#include "mxcore.h"

// VTABLE: LEGO1 0x100d4718
// SIZE 0x88
class LegoCacheSound : public MxCore {
public:
	LegoCacheSound();
	~LegoCacheSound() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10006580
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f01c4
		return "LegoCacheSound";
	}

	// FUNCTION: LEGO1 0x10006590
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoCacheSound::ClassName()) || MxCore::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x10006610
	// LegoCacheSound::`scalar deleting destructor'

private:
	void Init();

	undefined m_padding0x08[0x80]; // 0x08
};

#endif // LEGOCACHESOUND_H
