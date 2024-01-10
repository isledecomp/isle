#ifndef MXLOOPINGMIDIPRESENTER_H
#define MXLOOPINGMIDIPRESENTER_H

#include "mxmidipresenter.h"

// VTABLE: LEGO1 0x100dc240
// SIZE 0x58
class MxLoopingMIDIPresenter : public MxMIDIPresenter {
public:
	// FUNCTION: LEGO1 0x100b1830
	inline virtual const char* ClassName() const override // vtable+0xc
	{
		// STRING: LEGO1 0x10101de0
		return "MxLoopingMIDIPresenter";
	}

	// FUNCTION: LEGO1 0x100b1840
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxLoopingMIDIPresenter::ClassName()) || MxMIDIPresenter::IsA(p_name);
	}

	virtual void StreamingTickle() override; // vtable+0x20
	virtual void DoneTickle() override;      // vtable+0x2c
	virtual MxResult PutData() override;     // vtable+0x4c
};

// SYNTHETIC: LEGO1 0x100b19c0
// MxLoopingMIDIPresenter::`scalar deleting destructor'

#endif // MXLOOPINGMIDIPRESENTER_H
