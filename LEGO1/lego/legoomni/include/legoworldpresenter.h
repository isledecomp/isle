#ifndef LEGOWORLDPRESENTER_H
#define LEGOWORLDPRESENTER_H

#include "legoentitypresenter.h"

// VTABLE: LEGO1 0x100d8ee0
// SIZE 0x54
class LegoWorldPresenter : public LegoEntityPresenter {
public:
	LegoWorldPresenter();
	~LegoWorldPresenter() override; // vtable+0x00

	static void configureLegoWorldPresenter(MxS32 p_legoWorldPresenterQuality);

	// FUNCTION: LEGO1 0x10066630
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0608
		return "LegoWorldPresenter";
	}

	// FUNCTION: LEGO1 0x10066640
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoWorldPresenter::ClassName()) || LegoEntityPresenter::IsA(p_name);
	}

	void ReadyTickle() override;                                                           // vtable+0x18
	void StartingTickle() override;                                                        // vtable+0x1c
	void ParseExtra() override;                                                            // vtable+0x30
	MxResult StartAction(MxStreamController* p_controller, MxDSAction* p_action) override; // vtable+0x3c
	void VTable0x60(MxPresenter* p_presenter) override;                                    // vtable+0x60

	// SYNTHETIC: LEGO1 0x10066750
	// LegoWorldPresenter::`scalar deleting destructor'

private:
	undefined4 m_unk0x50;
};

#endif // LEGOWORLDPRESENTER_H
