#ifndef HOSPITAL_H
#define HOSPITAL_H

#include "actionsfwd.h"
#include "decomp.h"
#include "hospitalstate.h"
#include "legogamestate.h"
#include "legoworld.h"
#include "mxstillpresenter.h"
#include "radio.h"

// VTABLE: LEGO1 0x100d9730
// SIZE 0x12c
class Hospital : public LegoWorld {
public:
	Hospital();
	~Hospital() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x100746b0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0490
		return "Hospital";
	}

	// FUNCTION: LEGO1 0x100746c0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Hospital::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	inline void PlayAction(MxU32 p_objectId);

	// SYNTHETIC: LEGO1 0x100747d0
	// Hospital::`scalar deleting destructor'

private:
	MxLong HandleKeyPress(MxS8 p_key);
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleButtonDown(LegoControlManagerEvent& p_param);
	MxBool HandleClick(LegoControlManagerEvent& p_param);

	MxS16 m_currentActorId;             // 0xf8
	LegoGameState::Area m_destLocation; // 0xfc
	undefined2 m_unk0x100;              // 0x100
	HospitalState* m_hospitalState;     // 0x104
	undefined2 m_unk0x108;              // 0x108
	HospitalScript::Script m_unk0x10c;  // 0x10c
	MxStillPresenter* m_copLedBitmap;   // 0x110
	MxStillPresenter* m_pizzaLedBitmap; // 0x114
	undefined m_unk0x118;               // 0x118
	MxLong m_unk0x11c;                  // 0x11c
	MxLong m_unk0x120;                  // 0x120
	MxLong m_unk0x124;                  // 0x124
	undefined m_unk0x128;               // 0x128
};

#endif // HOSPITAL_H
