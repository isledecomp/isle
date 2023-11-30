#ifndef LEGO3DWAVEPRESENTER_H
#define LEGO3DWAVEPRESENTER_H

#include "legowavepresenter.h"

// VTABLE: LEGO1 0x100d52b0
// SIZE 0xa0
class Lego3DWavePresenter : public LegoWavePresenter {
public:
	// FUNCTION: LEGO1 0x1000d890
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f058c
		return "Lego3DWavePresenter";
	}

	// FUNCTION: LEGO1 0x1000d8a0
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Lego3DWavePresenter::ClassName()) || MxWavePresenter::IsA(name);
	}
};

#endif // LEGO3DWAVEPRESENTER_H
