#ifndef SCORE_H
#define SCORE_H

#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"

class LegoControlManagerEvent;
class MxEndActionNotificationParam;

// VTABLE: LEGO1 0x100d53f8
// SIZE 0x0c
class ScoreState : public LegoState {
public:
	// FUNCTION: LEGO1 0x1000de40
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0084
		return "ScoreState";
	}

	// FUNCTION: LEGO1 0x1000de50
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, ScoreState::ClassName()) || LegoState::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000de20
	MxBool IsSerializable() override { return FALSE; } // vtable+0x14

	// FUNCTION: LEGO1 0x1000de30
	MxBool SetFlag() override
	{
		m_playCubeTutorial = TRUE;
		return TRUE;
	} // vtable+0x18

	inline MxBool GetTutorialFlag() { return m_playCubeTutorial; }
	inline void SetTutorialFlag(MxBool p_playCubeTutorial) { m_playCubeTutorial = p_playCubeTutorial; }

	// SYNTHETIC: LEGO1 0x1000df00
	// ScoreState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	MxBool m_playCubeTutorial; // 0x08
};

// VTABLE: LEGO1 0x100d4018
// SIZE 0x104
class Score : public LegoWorld {
public:
	Score();
	~Score() override;
	MxLong Notify(MxParam& p_param) override; // vtable+0x04

	// FUNCTION: LEGO1 0x100010c0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0050
		return "Score";
	}

	// FUNCTION: LEGO1 0x100010d0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Score::ClassName()) || LegoWorld::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x100011e0
	// Score::`scalar deleting destructor'

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	void Paint();
	MxLong FUN_10001510(MxEndActionNotificationParam& p_param);
	MxLong FUN_100016d0(LegoControlManagerEvent& p_param);
	void FillArea(MxU32 i_activity, MxU32 i_actor, MxS16 score);

protected:
	void DeleteScript();

	LegoGameState::Area m_destLocation; // 0xf8
	ScoreState* m_state;                // 0xfc
	MxU8* m_surface;                    // 0x100
};

#endif // SCORE_H
