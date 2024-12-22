#ifndef HOSPITAL_H
#define HOSPITAL_H

#include "actionsfwd.h"
#include "decomp.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"

class LegoControlManagerNotificationParam;
class MxEndActionNotificationParam;
class MxStillPresenter;

// VTABLE: LEGO1 0x100d97a0
// VTABLE: BETA10 0x101b9ad8
// SIZE 0x18
class HospitalState : public LegoState {
public:
	// SIZE 0x04
	struct Unknown0x08 {
		undefined4 m_unk0x00; // 0x00
	};

	HospitalState();
	~HospitalState() override {}

	// FUNCTION: LEGO1 0x10076400
	// FUNCTION: BETA10 0x1002e3c0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0480
		return "HospitalState";
	}

	// FUNCTION: LEGO1 0x10076410
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HospitalState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_file) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x100764c0
	// HospitalState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	Unknown0x08 m_unk0x08; // 0x08
	MxS16 m_unk0x0c;       // 0x0c
	MxS16 m_unk0x0e;       // 0x0e
	MxS16 m_unk0x10;       // 0x10
	MxS16 m_unk0x12;       // 0x12
	MxS16 m_unk0x14;       // 0x14
	MxS16 m_unk0x16;       // 0x16
};

// VTABLE: LEGO1 0x100d9730
// VTABLE: BETA10 0x101b9a60
// SIZE 0x12c
class Hospital : public LegoWorld {
public:
	Hospital();
	~Hospital() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x100746b0
	// FUNCTION: BETA10 0x1002e1a0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0490
		return "Hospital";
	}

	// FUNCTION: LEGO1 0x100746c0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Hospital::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	inline void PlayAction(MxU32 p_objectId);

	// SYNTHETIC: LEGO1 0x100747d0
	// Hospital::`scalar deleting destructor'

private:
	MxLong HandleKeyPress(MxS8 p_key);
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleButtonDown(LegoControlManagerNotificationParam& p_param);
	MxBool HandleControl(LegoControlManagerNotificationParam& p_param);

	MxS16 m_currentActorId;                 // 0xf8
	LegoGameState::Area m_destLocation;     // 0xfc
	undefined2 m_unk0x100;                  // 0x100
	HospitalState* m_hospitalState;         // 0x104
	undefined2 m_unk0x108;                  // 0x108
	HospitalScript::Script m_currentAction; // 0x10c
	MxStillPresenter* m_copLedBitmap;       // 0x110
	MxStillPresenter* m_pizzaLedBitmap;     // 0x114
	undefined m_unk0x118;                   // 0x118
	MxLong m_copLedAnimTimer;               // 0x11c
	MxLong m_pizzaLedAnimTimer;             // 0x120
	MxLong m_time;                          // 0x124
	undefined m_unk0x128;                   // 0x128
};

#endif // HOSPITAL_H
