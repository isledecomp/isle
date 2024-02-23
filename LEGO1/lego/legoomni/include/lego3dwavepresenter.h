#ifndef LEGO3DWAVEPRESENTER_H
#define LEGO3DWAVEPRESENTER_H

#include "decomp.h"
#include "legounknown100d5778.h"
#include "mxwavepresenter.h"

// VTABLE: LEGO1 0x100d52b0
// SIZE 0xa0
class Lego3DWavePresenter : public MxWavePresenter {
public:
	// FUNCTION: LEGO1 0x1000d890
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f058c
		return "Lego3DWavePresenter";
	}

	// FUNCTION: LEGO1 0x1000d8a0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Lego3DWavePresenter::ClassName()) || MxWavePresenter::IsA(p_name);
	}

	void StartingTickle() override;   // vtable+0x1c
	void StreamingTickle() override;  // vtable+0x20
	MxResult AddToManager() override; // vtable+0x34
	void Destroy() override;          // vtable+0x38

	// SYNTHETIC: LEGO1 0x1000f4b0
	// Lego3DWavePresenter::`scalar deleting destructor'

private:
	undefined m_unk0x6c[4];        // 0x6c
	LegoUnknown100d5778 m_unk0x70; // 0x70
};

#endif // LEGO3DWAVEPRESENTER_H
