#ifndef LEGOFLCTEXTUREPRESENTER_H
#define LEGOFLCTEXTUREPRESENTER_H

#include "decomp.h"
#include "mxflcpresenter.h"

// VTABLE: LEGO1 0x100d89e0
// SIZE 0x70
class LegoFlcTexturePresenter : public MxFlcPresenter {
public:
	LegoFlcTexturePresenter();

	// FUNCTION: LEGO1 0x1005def0
	inline const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x100f0634
		return "LegoFlcTexturePresenter";
	}

private:
	void Init();

	undefined4 m_unk0x68; // 0x68
	undefined4 m_unk0x6c; // 0x6c
};

#endif // LEGOFLCTEXTUREPRESENTER_H
