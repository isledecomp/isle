#ifndef PIZZA_H
#define PIZZA_H

#include "actionsfwd.h"
#include "decomp.h"
#include "isleactor.h"
#include "legostate.h"

class Act1State;
class PizzeriaState;
class SkateBoard;

// VTABLE: LEGO1 0x100d7408
// VTABLE: BETA10 0x101bf750
// SIZE 0xb4
class PizzaMissionState : public LegoState {
public:
	// SIZE 0x20
	struct Mission {
		// FUNCTION: LEGO1 0x10039220
		// FUNCTION: BETA10 0x100ef880
		Mission() {}

		// FUNCTION: BETA10 0x100ef8a0
		Mission(
			MxU8 p_actorId,
			undefined2 p_unk0x04,
			MxLong* p_finishTimes,
			IsleScript::Script* p_actions,
			MxS16 p_numActions
		)
		{
			m_numActions = p_numActions;
			m_actorId = p_actorId;
			m_unk0x04 = p_unk0x04;
			m_unk0x06 = 1;
			m_unk0x08 = 1;
			m_finishTimes = p_finishTimes;
			m_startTime = INT_MIN;
			m_unk0x14 = 1;
			m_score = LegoState::e_grey;
			m_hiScore = LegoState::e_grey;
			m_actions = p_actions;
		}

		// FUNCTION: LEGO1 0x10039230
		Mission& operator=(const Mission& p_mission)
		{
			m_actorId = p_mission.m_actorId;
			m_unk0x04 = p_mission.m_unk0x04;
			m_unk0x06 = p_mission.m_unk0x06;
			m_unk0x08 = p_mission.m_unk0x08;
			m_finishTimes = p_mission.m_finishTimes;
			m_startTime = p_mission.m_startTime;
			m_unk0x14 = p_mission.m_unk0x14;
			m_score = p_mission.m_score;
			m_hiScore = p_mission.m_hiScore;
			m_actions = p_mission.m_actions;
			m_numActions = p_mission.m_numActions;
			return *this;
		}

		// FUNCTION: BETA10 0x100ef610
		IsleScript::Script GetRedFinishAction() { return m_actions[m_numActions + 6]; }

		// FUNCTION: BETA10 0x100ef640
		IsleScript::Script GetBlueFinishAction() { return m_actions[m_numActions + 7]; }

		// FUNCTION: BETA10 0x100ef670
		IsleScript::Script GetYellowFinishAction() { return m_actions[m_numActions + 8]; }

		// FUNCTION: BETA10 0x100ef6a0
		MxLong GetRedFinishTime() { return m_finishTimes[0]; }

		// FUNCTION: BETA10 0x100ef6d0
		MxLong GetBlueFinishTime() { return m_finishTimes[1]; }

		// FUNCTION: BETA10 0x100ef700
		void UpdateScore(ScoreColor p_score)
		{
			m_score = p_score;
			if (m_hiScore < p_score) {
				m_hiScore = p_score;
			}
		}

		// FUNCTION: BETA10 0x100ef780
		IsleScript::Script* GetActions() { return m_actions; }

		// FUNCTION: BETA10 0x100ef7b0
		IsleScript::Script GetUnknownFinishAction() { return m_actions[m_numActions + 2]; }

		// FUNCTION: BETA10 0x100ef7e0
		MxLong GetTimeoutTime() { return m_finishTimes[3]; }

		MxResult WriteToFile(LegoFile* p_file)
		{
			Write(p_file, m_unk0x06);
			Write(p_file, m_unk0x14);
			Write(p_file, m_score);
			Write(p_file, m_hiScore);
			return SUCCESS;
		}

		MxResult ReadFromFile(LegoFile* p_file)
		{
			Read(p_file, &m_unk0x06);
			Read(p_file, &m_unk0x14);
			Read(p_file, &m_score);
			Read(p_file, &m_hiScore);
			return SUCCESS;
		}

		MxS16 m_numActions;            // 0x00
		MxU8 m_actorId;                // 0x02
		undefined2 m_unk0x04;          // 0x04
		MxS16 m_unk0x06;               // 0x06
		undefined m_unk0x08;           // 0x08
		MxLong* m_finishTimes;         // 0x0c
		MxLong m_startTime;            // 0x10
		MxS16 m_unk0x14;               // 0x14
		MxS16 m_score;                 // 0x16
		MxS16 m_hiScore;               // 0x18
		IsleScript::Script* m_actions; // 0x1c
	};

	PizzaMissionState();

	// FUNCTION: LEGO1 0x10039290
	// FUNCTION: BETA10 0x100efa20
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00d4
		return "PizzaMissionState";
	}

	// FUNCTION: LEGO1 0x100392a0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, PizzaMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_file) override; // vtable+0x1c

	// FUNCTION: BETA10 0x100ef470
	void SetUnknown0xb0(MxU32 p_unk0xb0) { m_unk0xb0 = p_unk0xb0; }

	// FUNCTION: BETA10 0x100ef850
	MxU32 GetUnknown0xb0() { return m_unk0xb0; }

	MxS16 GetHighScore(MxU8 p_actorId) { return GetMission(p_actorId)->m_hiScore; }

	// SYNTHETIC: LEGO1 0x10039350
	// PizzaMissionState::`scalar deleting destructor'

	Mission* GetMission(MxU8 p_actorId);
	MxS16 FUN_10039540();

	PizzeriaState* m_pizzeriaState; // 0x08
	undefined4 m_unk0x0c;           // 0x0c
	Mission m_missions[5];          // 0x10
	MxU32 m_unk0xb0;                // 0xb0

	static IsleScript::Script g_pepperActions[];
	static IsleScript::Script g_mamaActions[];
	static IsleScript::Script g_papaActions[];
	static IsleScript::Script g_nickActions[];
	static IsleScript::Script g_lauraActions[];

	static MxLong g_pepperFinishTimes[];
	static MxLong g_mamaFinishTimes[];
	static MxLong g_papaFinishTimes[];
	static MxLong g_nickFinishTimes[];
	static MxLong g_lauraFinishTimes[];
};

// VTABLE: LEGO1 0x100d7380
// VTABLE: BETA10 0x101bf6b0
// SIZE 0x9c
class Pizza : public IsleActor {
public:
	Pizza();
	~Pizza() override;

	MxResult Tickle() override; // vtable+0x08

	// FUNCTION: LEGO1 0x10037f90
	// FUNCTION: BETA10 0x100ef300
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f038c
		return "Pizza";
	}

	// FUNCTION: LEGO1 0x10037fa0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Pizza::ClassName()) || IsleActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                           // vtable+0x18
	MxLong HandleClick() override;                                              // vtable+0x68
	MxLong HandleEndAction(MxEndActionNotificationParam& p_param) override;     // vtable+0x74
	MxLong HandlePathStruct(LegoPathStructNotificationParam& p_param) override; // vtable+0x80

	void CreateState();
	void FUN_10038220(IsleScript::Script p_objectId);
	void FUN_100382b0();
	void StopActions();
	void PlayAction(MxU32 p_objectId, MxBool p_param7);

	void SetSkateboard(SkateBoard* p_skateBoard) { m_skateBoard = p_skateBoard; }

	// SYNTHETIC: LEGO1 0x100380e0
	// Pizza::`scalar deleting destructor'

private:
	PizzaMissionState* m_state;            // 0x7c
	PizzaMissionState::Mission* m_mission; // 0x80
	SkateBoard* m_skateBoard;              // 0x84
	Act1State* m_act1state;                // 0x88
	IsleScript::Script m_unk0x8c;          // 0x8c
	MxLong m_unk0x90;                      // 0x90
	MxLong m_unk0x94;                      // 0x94
	MxBool m_unk0x98;                      // 0x98
};

#endif // PIZZA_H
