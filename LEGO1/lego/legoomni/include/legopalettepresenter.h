#ifndef LEGOPALETTEPRESENTER_H
#define LEGOPALETTEPRESENTER_H

#include "decomp.h"
#include "mxvideopresenter.h"

class MxPalette;

// VTABLE: LEGO1 0x100d9aa0
// SIZE 0x68
class LegoPalettePresenter : public MxVideoPresenter {
public:
	LegoPalettePresenter();
	~LegoPalettePresenter() override; // vtable+0x00

	// FUNCTION: BETA10 0x100ab250
	static const char* HandlerClassName()
	{
		// STRING: LEGO1 0x100f061c
		return "LegoPalettePresenter";
	}

	// FUNCTION: LEGO1 0x10079f30
	// FUNCTION: BETA10 0x100ab220
	const char* ClassName() const override // vtable+0x0c
	{
		return HandlerClassName();
	}

	// FUNCTION: LEGO1 0x10079f40
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ClassName()) || MxVideoPresenter::IsA(p_name);
	}

	void ReadyTickle() override; // vtable+0x18
	void Destroy() override;     // vtable+0x38

	MxResult ParsePalette(MxStreamChunk* p_chunk);

	// SYNTHETIC: LEGO1 0x1007a050
	// LegoPalettePresenter::`scalar deleting destructor'

private:
	void Init();
	void Destroy(MxBool p_fromDestructor);

	MxPalette* m_palette; // 0x64
};

#endif // LEGOPALETTEPRESENTER_H
