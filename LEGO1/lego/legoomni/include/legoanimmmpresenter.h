#ifndef LEGOANIMMMPRESENTER_H
#define LEGOANIMMMPRESENTER_H

#include "mxcompositepresenter.h"

class LegoWorld;

// VTABLE: LEGO1 0x100d7de8
// SIZE 0x74
class LegoAnimMMPresenter : public MxCompositePresenter {
public:
	LegoAnimMMPresenter();

	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x1004a950
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f046c
		return "LegoAnimMMPresenter";
	}

	// FUNCTION: LEGO1 0x1004a960
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimMMPresenter::ClassName()) || MxCompositePresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                           // vtable+0x18
	void StartingTickle() override;                                                        // vtable+0x1c
	void StreamingTickle() override;                                                       // vtable+0x20
	void RepeatingTickle() override;                                                       // vtable+0x24
	void DoneTickle() override;                                                            // vtable+0x2c
	void ParseExtra() override;                                                            // vtable+0x30
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void EndAction() override;                                                             // vtable+0x40
	void VTable0x60(MxPresenter* p_presenter) override;                                    // vtable+0x60

	// SYNTHETIC: LEGO1 0x1004aa40
	// LegoAnimMMPresenter::`scalar deleting destructor'

	MxBool FUN_1004b8b0();

private:
	MxPresenter* m_unk0x4c; // 0x4c
	undefined4 m_unk0x50;   // 0x50
	undefined4 m_unk0x54;   // 0x54
	undefined m_unk0x58;    // 0x58
	undefined m_unk0x59;    // 0x59
	undefined4 m_unk0x5c;   // 0x5c
	undefined4 m_unk0x60;   // 0x60
	LegoWorld* m_unk0x64;   // 0x64
	undefined4 m_unk0x68;   // 0x68
	undefined4 m_unk0x6c;   // 0x6c
	undefined4 m_unk0x70;   // 0x70
};

#endif // LEGOANIMMMPRESENTER_H
