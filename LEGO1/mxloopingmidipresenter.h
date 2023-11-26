#ifndef MXLOOPINGMIDIPRESENTER_H
#define MXLOOPINGMIDIPRESENTER_H

#include "mxmidipresenter.h"

// VTABLE 0x100dc240
// SIZE 0x58
class MxLoopingMIDIPresenter : public MxMIDIPresenter {
public:
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// 0x10101de0
		return "MxLoopingMIDIPresenter";
	}

	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, MxLoopingMIDIPresenter::ClassName()) || MxMIDIPresenter::IsA(name);
	}

	virtual void StreamingTickle() override; // vtable+0x20
	virtual void DoneTickle() override;      // vtable+0x2c
	virtual MxResult PutData() override;     // vtable+0x4c
};

#endif // MXLOOPINGMIDIPRESENTER_H
