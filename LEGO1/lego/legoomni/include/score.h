#ifndef SCORE_H
#define SCORE_H

#include "legoeventnotificationparam.h"
#include "legoworld.h"
#include "mxactionnotificationparam.h"
#include "mxtype17notificationparam.h"
#include "scorestate.h"

// VTABLE: LEGO1 0x100d4018
// SIZE 0x104
class Score : public LegoWorld {
public:
	Score();
	virtual ~Score() override;                        // vtable+0x0
	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4

	// FUNCTION: LEGO1 0x100010c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0050
		return "Score";
	}

	// FUNCTION: LEGO1 0x100010d0
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Score::ClassName()) || LegoWorld::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x100011e0
	// Score::`scalar deleting destructor'

	virtual MxResult Create(MxDSAction& p_dsAction) override; // vtable+18
	virtual void VTable0x50() override;                       // vtable+50
	virtual MxBool VTable0x5c() override;                     // vtable+5c
	virtual MxBool VTable0x64() override;                     // vtable+64
	virtual void VTable0x68(MxBool p_add) override;           // vtable+68

	void Paint();
	MxLong FUN_10001510(MxEndActionNotificationParam& p_param);
	MxLong FUN_100016d0(MxType17NotificationParam& p_param);
	void FillArea(MxU32 p_x, MxU32 p_y, MxS16 p_color);

protected:
	undefined4 m_unk0xf8;
	ScoreState* m_state;
	MxU8* m_surface;

private:
	void DeleteScript();
};

#endif // SCORE_H
