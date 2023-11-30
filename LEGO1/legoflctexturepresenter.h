#ifndef LEGOFLCTEXTUREPRESENTER_H
#define LEGOFLCTEXTUREPRESENTER_H

#include "mxflcpresenter.h"

// VTABLE: LEGO1 0x100d89e0
// SIZE 0x70
class LegoFlcTexturePresenter : public MxFlcPresenter {
public:
	LegoFlcTexturePresenter();

	// FUNCTION: LEGO1 0x1005def0
	inline const char* ClassName() const override // vtable+0xc
	{
		// GLOBAL: LEGO1 0x100f0634
		return "LegoFlcTexturePresenter";
	}
};

#endif // LEGOFLCTEXTUREPRESENTER_H
