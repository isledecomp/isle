#ifndef JUKEBOX_H
#define JUKEBOX_H

#include "decomp.h"
#include "jukeboxstate.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoworld.h"

// VTABLE: LEGO1 0x100d8958
// SIZE 0x104
class JukeBox : public LegoWorld {
public:
	JukeBox();
	~JukeBox() override;

	MxLong Notify(MxParam& p_param) override; // vtable+0x04
	MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1005d6f0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f02cc
		return "JukeBox";
	}

	// FUNCTION: LEGO1 0x1005d700
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JukeBox::ClassName()) || LegoWorld::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	void ReadyWorld() override;                       // vtable+0x50
	MxBool VTable0x5c() override;                     // vtable+0x5c
	MxBool VTable0x64() override;                     // vtable+0x64
	void Enable(MxBool p_enable) override;            // vtable+0x68

	// SYNTHETIC: LEGO1 0x1005d810
	// JukeBox::`scalar deleting destructor'

private:
	MxBool HandleClick(LegoControlManagerEvent& p_param);

	LegoGameState::Area m_destLocation; // 0xf8
	JukeBoxState* m_state;              // 0xfc
	undefined2 m_unk0x100;              // 0x100
};

#endif // JUKEBOX_H
