#ifndef DUNEBUGGY_H
#define DUNEBUGGY_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d8f98
// SIZE 0x16c
class DuneBuggy : public IslePathActor {
public:
	DuneBuggy();

	// FUNCTION: LEGO1 0x10067c30
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0410
		return "DuneBuggy";
	}

	// FUNCTION: LEGO1 0x10067c40
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, DuneBuggy::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                            // vtable+0x18
	void Animate(float p_time) override;                                         // vtable+0x70
	MxLong HandleClick() override;                                               // vtable+0xcc
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param) override; // vtable+0xd4
	MxLong HandlePathStruct(LegoPathStructNotificationParam& p_param) override;  // vtable+0xdc
	void Exit() override;                                                        // vtable+0xe4

	void ActivateSceneActions();

	static MxS32 GetColorOffset(const char* p_variable);

	// SYNTHETIC: LEGO1 0x10067dc0
	// DuneBuggy::`scalar deleting destructor'

private:
	MxS16 m_dashboard; // 0x160
	MxFloat m_fuel;    // 0x164
	MxFloat m_time;    // 0x168
};

#endif // DUNEBUGGY_H
