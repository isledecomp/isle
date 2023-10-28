#ifndef MXLOOPINGMIDIPRESENTER_H
#define MXLOOPINGMIDIPRESENTER_H

#include "mxmidipresenter.h"

// VTABLEADDR 0x100dc240
// SIZE 0x58
class MxLoopingMIDIPresenter : public MxMIDIPresenter {
public:
	// OFFSET: LEGO1 0x100b1830
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x10101de0
		return "MxLoopingMIDIPresenter";
	}

	// OFFSET: LEGO1 0x100b1840
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxLoopingMIDIPresenter::ClassName()) || MxMIDIPresenter::IsA(name);
	}
};

#endif // MXLOOPINGMIDIPRESENTER_H
