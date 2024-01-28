#ifndef LEGO3DWAVEPRESENTER_H
#define LEGO3DWAVEPRESENTER_H

#include "mxwavepresenter.h"

// VTABLE: LEGO1 0x100d52b0
// SIZE 0xa0
class Lego3DWavePresenter : public MxWavePresenter {
public:
	// FUNCTION: LEGO1 0x1000d890
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f058c
		return "Lego3DWavePresenter";
	}

	// FUNCTION: LEGO1 0x1000d8a0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Lego3DWavePresenter::ClassName()) || MxWavePresenter::IsA(p_name);
	}

	virtual void StartingTickle() override;   // vtable+0x1c
	virtual void StreamingTickle() override;  // vtable+0x20
	virtual MxResult AddToManager() override; // vtable+0x34
	virtual void Destroy() override;          // vtable+0x38

	// SYNTHETIC: LEGO1 0x1000f4b0
	// Lego3DWavePresenter::`scalar deleting destructor'
};

#endif // LEGO3DWAVEPRESENTER_H
