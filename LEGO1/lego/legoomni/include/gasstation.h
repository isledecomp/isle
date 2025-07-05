#ifndef GASSTATION_H
#define GASSTATION_H

#include "decomp.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"
#include "radio.h"

class MxStillPresenter;

// VTABLE: LEGO1 0x100d46e0
// VTABLE: BETA10 0x101b9818
// SIZE 0x24
class GasStationState : public LegoState {
public:
	enum {
		e_unknown0 = 0,
		e_newState = 1,
		e_beforeExitingForQuest = 2,
		e_unknown3 = 3,
		e_unknown4 = 4,
		e_introduction = 5,
		e_explainQuest = 6,
		e_waitAcceptingQuest = 7,
		e_afterAcceptingQuest = 8,
		e_cancelQuest = 9,
	};

	GasStationState();

	// FUNCTION: LEGO1 0x100061d0
	// FUNCTION: BETA10 0x10029f50
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0174
		return "GasStationState";
	}

	// FUNCTION: LEGO1 0x100061e0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStationState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoStorage* p_storage) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x10006290
	// GasStationState::`scalar deleting destructor'

	void PlayAction(GarageScript::Script p_objectId);
	void StopAction(GarageScript::Script p_objectId);
	void StopActions();

	// TODO: Most likely getters/setters are not used according to BETA.

	GarageScript::Script m_actions[3]; // 0x08
	MxS32 m_state;                     // 0x14
	MxS16 m_pepperAction;              // 0x18
	MxS16 m_mamaAction;                // 0x1a
	MxS16 m_papaAction;                // 0x1c
	MxS16 m_nickAction;                // 0x1e
	MxS16 m_lauraAction;               // 0x20
};

// VTABLE: LEGO1 0x100d4650
// VTABLE: BETA10 0x101b97a0
// SIZE 0x128
class GasStation : public LegoWorld {
public:
	GasStation();
	~GasStation() override; // vtable+0x00

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10004770
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x10004780
	// FUNCTION: BETA10 0x10029d40
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0168
		return "GasStation";
	}

	// FUNCTION: LEGO1 0x10004790
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, GasStation::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                           // vtable+0x18
	void ReadyWorld() override;                                                 // vtable+0x50
	MxBool Escape() override;                                                   // vtable+0x64
	void Enable(MxBool p_enable) override;                                      // vtable+0x68
	virtual MxLong HandleControl(LegoControlManagerNotificationParam& p_param); // vtable+0x6c

	// SYNTHETIC: LEGO1 0x100048a0
	// GasStation::`scalar deleting destructor'

private:
	enum {
		e_finished = 0,
		e_start = 1,
		e_started = 2,
		e_canceled = 3,
	};

	inline void PlayAction(GarageScript::Script p_objectId);
	inline void StopAction(GarageScript::Script p_objectId);

	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleKeyPress(MxS8 p_key);
	MxLong HandleButtonDown(LegoControlManagerNotificationParam& p_param);

	MxS16 m_currentActorId;             // 0xf8
	undefined2 m_unk0xfa;               // 0xfa
	LegoGameState::Area m_destLocation; // 0xfc
	GasStationState* m_state;           // 0x100
	MxS16 m_waitingState;               // 0x104
	MxS16 m_setWithCurrentAction;       // 0x106
	MxStillPresenter* m_trackLedBitmap; // 0x108
	MxLong m_lastIdleAnimation;         // 0x10c
	MxLong m_trackLedTimer;             // 0x110
	MxBool m_waiting;                   // 0x114
	MxBool m_flashingLeds;              // 0x115
	Radio m_radio;                      // 0x118
};

#endif // GASSTATION_H
