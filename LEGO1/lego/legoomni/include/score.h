#ifndef SCORE_H
#define SCORE_H

#include "legocontrolmanager.h"
#include "legoeventnotificationparam.h"
#include "legogamestate.h"
#include "legoworld.h"
#include "mxactionnotificationparam.h"
#include "scorestate.h"

// VTABLE: LEGO1 0x100d4018
// SIZE 0x104
class Score : public LegoWorld {
public:
	Score();
	~Score() override;                        // vtable+0x00
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

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+18
	void ReadyWorld() override;                       // vtable+50
	MxBool VTable0x5c() override;                     // vtable+5c
	MxBool VTable0x64() override;                     // vtable+64
	void Enable(MxBool p_enable) override;            // vtable+68

	void Paint();
	MxLong FUN_10001510(MxEndActionNotificationParam& p_param);
	MxLong FUN_100016d0(LegoControlManagerEvent& p_param);
	void FillArea(MxU32 p_x, MxU32 p_y, MxS16 p_color);

protected:
	LegoGameState::Area m_destLocation;
	ScoreState* m_state;
	MxU8* m_surface;

private:
	void DeleteScript();
};

#endif // SCORE_H
