#ifndef SKATEBOARD_H
#define SKATEBOARD_H

#include "decomp.h"
#include "islepathactor.h"

class Act1State;

// VTABLE: LEGO1 0x100d55f0
// VTABLE: BETA10 0x101bfc70
// SIZE 0x168
class SkateBoard : public IslePathActor {
public:
	SkateBoard();
	~SkateBoard() override;

	// FUNCTION: LEGO1 0x1000fdd0
	// FUNCTION: BETA10 0x100f55d0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f041c
		return "SkateBoard";
	}

	// FUNCTION: LEGO1 0x1000fde0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, SkateBoard::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                            // vtable+0x18
	MxLong HandleClick() override;                                               // vtable+0xcc
	MxLong HandleNotification0() override;                                       // vtable+0xd0
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param) override; // vtable+0xd4
	void Exit() override;                                                        // vtable+0xe4

	void SetUnknown0x160(MxBool p_unk0x160) { m_unk0x160 = p_unk0x160; }

	void ActivateSceneActions();
	void EnableScenePresentation(MxBool p_enable);

	// SYNTHETIC: LEGO1 0x1000ff60
	// SkateBoard::`scalar deleting destructor'

private:
	MxBool m_unk0x160;      // 0x160
	Act1State* m_act1state; // 0x164
};

#endif // SKATEBOARD_H
