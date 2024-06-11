#ifndef AMBULANCE_H
#define AMBULANCE_H

#include "islepathactor.h"
#include "legostate.h"

class MxEndActionNotificationParam;

// VTABLE: LEGO1 0x100d72a0
// SIZE 0x24
class AmbulanceMissionState : public LegoState {
public:
	AmbulanceMissionState();

	// FUNCTION: LEGO1 0x10037600
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00e8
		return "AmbulanceMissionState";
	}

	// FUNCTION: LEGO1 0x10037610
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, AmbulanceMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_legoFile) override; // vtable+0x1c

	inline MxU16 GetScore(MxU8 p_id)
	{
		switch (p_id) {
		case 1:
			return m_score1;
		case 2:
			return m_score2;
		case 3:
			return m_score3;
		case 4:
			return m_score4;
		case 5:
			return m_score5;
		default:
			return 0;
		}
	}

	// SYNTHETIC: LEGO1 0x100376c0
	// AmbulanceMissionState::`scalar deleting destructor'

	undefined4 m_unk0x08; // 0x08
	undefined4 m_unk0x0c; // 0x0c
	MxU16 m_unk0x10;      // 0x10
	MxU16 m_unk0x12;      // 0x12
	MxU16 m_unk0x14;      // 0x14
	MxU16 m_unk0x16;      // 0x16
	MxU16 m_unk0x18;      // 0x18
	MxU16 m_score1;       // 0x1a
	MxU16 m_score2;       // 0x1c
	MxU16 m_score3;       // 0x1e
	MxU16 m_score4;       // 0x20
	MxU16 m_score5;       // 0x22
};

// VTABLE: LEGO1 0x100d71a8
// SIZE 0x184
class Ambulance : public IslePathActor {
public:
	Ambulance();
	~Ambulance() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x10035fa0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03c4
		return "Ambulance";
	}

	// FUNCTION: LEGO1 0x10035fb0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Ambulance::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                         // vtable+0x18
	void Destroy(MxBool p_fromDestructor) override;                           // vtable+0x1c
	void VTable0x70(float p_float) override;                                  // vtable+0x70
	MxLong HandleClick() override;                                            // vtable+0xcc
	MxLong HandleControl(LegoControlManagerEvent& p_param) override;          // vtable+0xd4
	MxLong HandleNotification19(MxType19NotificationParam& p_param) override; // vtable+0xdc
	void Exit() override;                                                     // vtable+0xe4
	virtual MxLong HandleButtonDown(LegoControlManagerEvent& p_param);        // vtable+0xf0
	virtual MxLong HandleEndAction(MxEndActionNotificationParam& p_param);    // vtable+0xf4

	void CreateState();
	void FUN_10036e60();
	void FUN_10037060();
	void StopActions();
	void FUN_10037250();

	// SYNTHETIC: LEGO1 0x10036130
	// Ambulance::`scalar deleting destructor'

private:
	void PlayAnimation(IsleScript::Script p_objectId);
	void StopAction(IsleScript::Script p_objectId);
	void PlayAction(IsleScript::Script p_objectId);

	undefined m_unk0x160[4];            // 0x160
	AmbulanceMissionState* m_state;     // 0x164
	MxS16 m_unk0x168;                   // 0x168
	MxS16 m_unk0x16a;                   // 0x16a
	MxS16 m_unk0x16c;                   // 0x16c
	MxS16 m_unk0x16e;                   // 0x16e
	MxS16 m_unk0x170;                   // 0x170
	MxS16 m_unk0x172;                   // 0x172
	IsleScript::Script m_lastAction;    // 0x174
	IsleScript::Script m_lastAnimation; // 0x178
	MxFloat m_unk0x17c;                 // 0x17c
	MxFloat m_time;                     // 0x180
};

#endif // AMBULANCE_H
