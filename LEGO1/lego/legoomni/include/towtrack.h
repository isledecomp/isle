#ifndef TOWTRACK_H
#define TOWTRACK_H

#include "decomp.h"
#include "islepathactor.h"
#include "legostate.h"

class MxEndActionNotificationParam;

// VTABLE: LEGO1 0x100d7fd8
// SIZE 0x28
class TowTrackMissionState : public LegoState {
public:
	TowTrackMissionState();

	// FUNCTION: LEGO1 0x1004dfa0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00bc
		return "TowTrackMissionState";
	}

	// FUNCTION: LEGO1 0x1004dfb0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, TowTrackMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_file) override; // vtable+0x1c

	MxS16 GetHighScore(MxU8 p_actorId)
	{
		switch (p_actorId) {
		case LegoActor::c_pepper:
			return m_peHighScore;
		case LegoActor::c_mama:
			return m_maHighScore;
		case LegoActor::c_papa:
			return m_paHighScore;
		case LegoActor::c_nick:
			return m_niHighScore;
		case LegoActor::c_laura:
			return m_laHighScore;
		default:
			return 0;
		}
	}

	// FUNCTION: BETA10 0x100f8530
	void UpdateScore(ScoreColor p_score, MxS16 p_actorId)
	{
		switch (p_actorId) {
		case LegoActor::c_pepper:
			m_peScore = p_score;
			if (m_peHighScore < p_score) {
				m_peHighScore = p_score;
			}
			break;
		case LegoActor::c_mama:
			m_maScore = p_score;
			if (m_maHighScore < p_score) {
				m_maHighScore = p_score;
			}
			break;
		case LegoActor::c_papa:
			m_paScore = p_score;
			if (m_paHighScore < p_score) {
				m_paHighScore = p_score;
			}
			break;
		case LegoActor::c_nick:
			m_niScore = p_score;
			if (m_niHighScore < p_score) {
				m_niHighScore = p_score;
			}
			break;
		case LegoActor::c_laura:
			m_laScore = p_score;
			if (m_laHighScore < p_score) {
				m_laHighScore = p_score;
			}
			break;
		}
	}

	// SYNTHETIC: LEGO1 0x1004e060
	// TowTrackMissionState::`scalar deleting destructor'

	undefined4 m_unk0x08; // 0x08
	MxLong m_startTime;   // 0x0c
	MxBool m_unk0x10;     // 0x10
	MxS16 m_peScore;      // 0x12
	MxS16 m_maScore;      // 0x14
	MxS16 m_paScore;      // 0x16
	MxS16 m_niScore;      // 0x18
	MxS16 m_laScore;      // 0x1a
	MxS16 m_peHighScore;  // 0x1c
	MxS16 m_maHighScore;  // 0x1e
	MxS16 m_paHighScore;  // 0x20
	MxS16 m_niHighScore;  // 0x22
	MxS16 m_laHighScore;  // 0x24
};

// VTABLE: LEGO1 0x100d7ee0
// SIZE 0x180
class TowTrack : public IslePathActor {
public:
	TowTrack();
	~TowTrack() override;

	// FUNCTION: LEGO1 0x1004c7c0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03b8
		return "TowTrack";
	}

	// FUNCTION: LEGO1 0x1004c7d0
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, TowTrack::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxLong Notify(MxParam& p_param) override;                                    // vtable+0x04
	MxResult Create(MxDSAction& p_dsAction) override;                            // vtable+0x18
	void Animate(float p_time) override;                                         // vtable+0x70
	MxLong HandleClick() override;                                               // vtable+0xcc
	MxLong HandleControl(LegoControlManagerNotificationParam& p_param) override; // vtable+0xd4
	MxLong HandleEndAnim(LegoEndAnimNotificationParam& p_param) override;        // vtable+0xd8
	MxLong HandlePathStruct(LegoPathStructNotificationParam& p_param) override;  // vtable+0xdc
	void Exit() override;                                                        // vtable+0xe4
	virtual MxLong HandleEndAction(MxEndActionNotificationParam& p_param);       // vtable+0xf0

	void CreateState();
	void FUN_1004dab0();
	void ActivateSceneActions();
	void StopActions();
	void FUN_1004dbe0();

	// SYNTHETIC: LEGO1 0x1004c950
	// TowTrack::`scalar deleting destructor'

private:
	void Leave();
	void PlayFinalAnimation(IsleScript::Script p_objectId);
	void FUN_1004dcb0(IsleScript::Script p_objectId);
	void PlayAction(IsleScript::Script p_objectId);

	undefined4 m_unk0x160;              // 0x160
	TowTrackMissionState* m_state;      // 0x164
	MxS16 m_unk0x168;                   // 0x168
	MxS16 m_actorId;                    // 0x16a
	MxS16 m_unk0x16c;                   // 0x16c
	MxS16 m_unk0x16e;                   // 0x16e
	IsleScript::Script m_lastAction;    // 0x170
	IsleScript::Script m_lastAnimation; // 0x174
	MxFloat m_fuel;                     // 0x178
	MxFloat m_time;                     // 0x17c
};

#endif // TOWTRACK_H
