#ifndef JUKEBOXSTATE_H
#define JUKEBOXSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d4a90
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

	// FUNCTION: LEGO1 0x1000f310
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f02bc
		return "JukeBoxState";
	}

	// FUNCTION: LEGO1 0x1000f320
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, JukeBoxState::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool IsSerializable() override; // vtable+0x14

	// SYNTHETIC: LEGO1 0x1000f3d0
	// JukeBoxState::`scalar deleting destructor'

	Music m_music;  // 0x08
	MxU32 m_active; // 0x0c
};

#endif // JUKEBOXSTATE_H
