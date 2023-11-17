#ifndef LEGOPALETTEPRESENTER_H
#define LEGOPALETTEPRESENTER_H

#include "decomp.h"
#include "mxpalette.h"
#include "mxvideopresenter.h"

// VTABLE 0x100d9aa0
// SIZE 0x68
class LegoPalettePresenter : public MxVideoPresenter {
public:
	LegoPalettePresenter();
	virtual ~LegoPalettePresenter(); // vtable+0x0

	// OFFSET: LEGO1 0x10079f30
	inline const char* ClassName() const override // vtable+0xc
	{
		// 0x100f061c
		return "LegoPalettePresenter";
	}

	// OFFSET: LEGO1 0x10079f40
	inline MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, ClassName()) || MxVideoPresenter::IsA(name);
	}

	virtual void Destroy(); // vtable+0x38
private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	MxPalette* m_palette;
};

#endif // LEGOPALETTEPRESENTER_H
