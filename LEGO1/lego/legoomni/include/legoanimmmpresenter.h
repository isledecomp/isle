#ifndef LEGOANIMMMPRESENTER_H
#define LEGOANIMMMPRESENTER_H

#include "mxcompositepresenter.h"

// VTABLE: LEGO1 0x100d7de8
// SIZE 0x74
class LegoAnimMMPresenter : public MxCompositePresenter {
public:
	LegoAnimMMPresenter();

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1004a950
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f046c
		return "LegoAnimMMPresenter";
	}

	// FUNCTION: LEGO1 0x1004a960
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimMMPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}

	virtual void ReadyTickle() override;                                                           // vtable+0x18
	virtual void StartingTickle() override;                                                        // vtable+0x1c
	virtual void StreamingTickle() override;                                                       // vtable+0x20
	virtual void RepeatingTickle() override;                                                       // vtable+0x24
	virtual void DoneTickle() override;                                                            // vtable+0x2c
	virtual void ParseExtra() override;                                                            // vtable+0x30
	virtual MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	virtual void EndAction() override;                                                             // vtable+0x40
	virtual void VTable0x60(MxPresenter* p_presenter) override;                                    // vtable+0x60

	// SYNTHETIC: LEGO1 0x1004aa40
	// LegoAnimMMPresenter::`scalar deleting destructor'
};

#endif // LEGOANIMMMPRESENTER_H
