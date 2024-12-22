#ifndef LEGOACT2_H
#define LEGOACT2_H

#include "act2brick.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"

class Act2Actor;
class LegoPathStructNotificationParam;
class MxEndActionNotificationParam;

// VTABLE: LEGO1 0x100d4a70
// VTABLE: BETA10 0x101ba910
// SIZE 0x10
class LegoAct2State : public LegoState {
public:
	LegoAct2State()
	{
		m_unk0x08 = 0;
		m_enabled = FALSE;
	}
	~LegoAct2State() override {}

	// FUNCTION: LEGO1 0x1000df80
	// FUNCTION: BETA10 0x1003c7e0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0428
		return "LegoAct2State";
	}

	// FUNCTION: LEGO1 0x1000df90
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAct2State::ClassName()) || LegoState::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000df70
	MxBool IsSerializable() override { return FALSE; } // vtable+0x14

	// SYNTHETIC: LEGO1 0x1000e040
	// LegoAct2State::`scalar deleting destructor'

	// FUNCTION: BETA10 0x100151b0
	void SetUnknown0x08(undefined4 p_unk0x08) { m_unk0x08 = p_unk0x08; }

	undefined4 GetUnknown0x08() { return m_unk0x08; }

	// TODO: Most likely getters/setters are not used according to BETA. (?)

	undefined4 m_unk0x08; // 0x08
	MxBool m_enabled;     // 0x0c
};

// VTABLE: LEGO1 0x100d82e0
// VTABLE: BETA10 0x101ba898
// SIZE 0x1154
class LegoAct2 : public LegoWorld {
public:
	LegoAct2();
	~LegoAct2() override;

	MxLong Notify(MxParam& p_param) override;         // vtable+0x04
	MxResult Tickle() override;                       // vtable+0x08
	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	void VTable0x60() override;                       // vtable+0x60
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	void SetUnknown0x1138(Act2Actor* p_unk0x1138) { m_unk0x1138 = p_unk0x1138; }
	void SetDestLocation(LegoGameState::Area p_destLocation) { m_destLocation = p_destLocation; }

	MxResult FUN_100516b0();
	void FUN_100517b0();
	MxResult BadEnding();
	MxResult FUN_10052560(
		Act2mainScript::Script p_objectId,
		MxBool p_param2,
		MxBool p_param3,
		Mx3DPointFloat* p_location,
		Mx3DPointFloat* p_direction,
		Mx3DPointFloat* p_param6
	);

	// SYNTHETIC: LEGO1 0x1004fe20
	// LegoAct2::`scalar deleting destructor'

private:
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param);
	MxLong HandleTransitionEnd();
	MxLong HandlePathStruct(LegoPathStructNotificationParam& p_param);
	void PlayMusic(JukeboxScript::Script p_objectId);
	void FUN_10051900();
	void FUN_10051960();
	void InitBricks();
	void UninitBricks();
	void SpawnBricks();
	void FUN_10051fa0(MxS32 p_param1);
	void FUN_100521f0(MxS32 p_param1);
	MxResult FUN_10052800();

	Act2Brick m_bricks[10];        // 0x00f8
	MxU8 m_nextBrick;              // 0x10c0
	undefined m_unk0x10c1;         // 0x10c1
	MxBool m_ready;                // 0x10c2
	undefined4 m_unk0x10c4;        // 0x10c4
	JukeboxScript::Script m_music; // 0x10c8
	LegoAct2State* m_gameState;    // 0x10cc
	MxS32 m_unk0x10d0;             // 0x10d0

	// variable name verified by BETA10 0x10014633
	const char* m_siFile; // 0x10d4

	LegoROI* m_pepper;                  // 0x10d8
	MxMatrix m_unk0x10dc;               // 0x10dc
	LegoPathBoundary* m_unk0x1124;      // 0x1124
	LegoROI* m_ambulance;               // 0x1128
	undefined4 m_unk0x112c;             // 0x112c
	undefined4 m_unk0x1130;             // 0x1130
	undefined4 m_unk0x1134;             // 0x1134
	Act2Actor* m_unk0x1138;             // 0x1138
	undefined m_unk0x113c;              // 0x113c
	Act2mainScript::Script m_unk0x1140; // 0x1140
	Act2mainScript::Script m_unk0x1144; // 0x1144
	undefined4 m_unk0x1148;             // 0x1148
	undefined m_firstBrick;             // 0x114c
	undefined m_secondBrick;            // 0x114d
	undefined m_thirdBrick;             // 0x114e
	undefined m_fourthBrick;            // 0x114e
	LegoGameState::Area m_destLocation; // 0x1150
};

#endif // LEGOACT2_H
