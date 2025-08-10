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
	enum {
		e_exitToClose = 0,
		e_newState = 1,
		e_unknown3 = 3,
		e_unknown4 = 4,
		e_introduction = 5,
		e_explainQuestShort = 6,
		e_explainQuest = 7,
		e_waitAcceptingQuest = 8,
		e_beforeEnteringAmbulance = 9,
		e_unknown10 = 10, // Can never be reached
		e_unknown11 = 11, // Can only be reached via e_unknown10
		e_afterAcceptingQuest = 12,
		e_exitImmediately = 13,
		e_exitToInfocenter = 14,
		e_exitToFront = 15,
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

	MxResult Serialize(LegoStorage* p_storage) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x100764c0
	// HospitalState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	MxS32 m_state;       // 0x08
	MxS16 m_stateActor;  // 0x0c
	MxS16 m_statePepper; // 0x0e
	MxS16 m_stateMama;   // 0x10
	MxS16 m_statePapa;   // 0x12
	MxS16 m_stateNick;   // 0x14
	MxS16 m_stateLaura;  // 0x16
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

	// FUNCTION: LEGO1 0x100746a0
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

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
	MxU16 m_interactionMode;                // 0x100
	HospitalState* m_hospitalState;         // 0x104
	MxU16 m_setWithCurrentAction;           // 0x108
	HospitalScript::Script m_currentAction; // 0x10c
	MxStillPresenter* m_copLedBitmap;       // 0x110
	MxStillPresenter* m_pizzaLedBitmap;     // 0x114
	MxBool m_flashingLeds;                  // 0x118
	MxLong m_copLedAnimTimer;               // 0x11c
	MxLong m_pizzaLedAnimTimer;             // 0x120
	MxLong m_time;                          // 0x124
	MxBool m_exited;                        // 0x128
};

#endif // HOSPITAL_H
