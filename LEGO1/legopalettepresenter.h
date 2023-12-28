#ifndef LEGOPALETTEPRESENTER_H
#define LEGOPALETTEPRESENTER_H

#include "decomp.h"
#include "mxpalette.h"
#include "mxvideopresenter.h"

// VTABLE: LEGO1 0x100d9aa0
// SIZE 0x68
class LegoPalettePresenter : public MxVideoPresenter {
public:
	LegoPalettePresenter();
	virtual ~LegoPalettePresenter() override; // vtable+0x0

	// FUNCTION: LEGO1 0x10079f30
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f061c
		return "LegoPalettePresenter";
	}

	// FUNCTION: LEGO1 0x10079f40
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override; // vtable+0x18
	virtual void Destroy() override;     // vtable+0x38

	MxResult ParsePallete(MxStreamChunk* p_chunk);

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	MxPalette* m_palette; // 0x64
};

#endif // LEGOPALETTEPRESENTER_H
