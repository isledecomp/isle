#ifndef JUKEBOX_H
#define JUKEBOX_H

#include "decomp.h"
#include "legogamestate.h"
#include "legostate.h"
#include "legoworld.h"

class LegoControlManagerNotificationParam;

// VTABLE: LEGO1 0x100d4a90
// VTABLE: BETA10 0x101ba6e8
// SIZE 0x10
class JukeBoxState : public LegoState {
public:
	enum Music {
		e_pasquell = 0,
		e_right,
		e_decal,
		e_wallis,
		e_nelson,
		e_torpedos
	};

	JukeBoxState() : m_music(e_pasquell), m_active(FALSE) {}

	// FUNCTION: LEGO1 0x1000f300
	MxBool IsSerializable() override { return FALSE; } // vtable+0x14

	// FUNCTION: LEGO1 0x1000f310
	// FUNCTION: BETA10 0x100389c0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f02bc
		return "JukeBoxState";
	}

	// FUNCTION: LEGO1 0x1000f320
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JukeBoxState::ClassName()) || LegoState::IsA(p_name);
	}

	// SYNTHETIC: LEGO1 0x1000f3d0
	// JukeBoxState::`scalar deleting destructor'

	Music m_music;  // 0x08
	MxU32 m_active; // 0x0c
};

// VTABLE: LEGO1 0x100d8958
// VTABLE: BETA10 0x101ba670
// SIZE 0x104
class JukeBox : public LegoWorld {
public:
	JukeBox();
	~JukeBox() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1005d6e0
	MxBool EnabledAfterDestruction() override { return TRUE; } // vtable+0x5c

	// FUNCTION: LEGO1 0x1005d6f0
	// FUNCTION: BETA10 0x100388d0
	const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f02cc
		return "JukeBox";
	}

	// FUNCTION: LEGO1 0x1005d700
	MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JukeBox::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool Escape() override;                         // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1005d810
	// JukeBox::`scalar deleting destructor'

private:
	MxBool HandleControl(LegoControlManagerNotificationParam& p_param);

	LegoGameState::Area m_destLocation; // 0xf8
	JukeBoxState* m_state;              // 0xfc
	undefined2 m_unk0x100;              // 0x100
};

#endif // JUKEBOX_H
