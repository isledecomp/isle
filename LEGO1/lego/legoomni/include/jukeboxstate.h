#ifndef JUKEBOXSTATE_H
#define JUKEBOXSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d4a90
// SIZE 0x10
class JukeBoxState : public LegoState {
public:
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

	MxBool VTable0x14() override; // vtable+0x14

	inline MxU32 IsActive() { return m_active; }
	inline void SetActive(MxU32 p_active) { m_active = p_active; }
	inline MxU32 GetState() { return m_state; }
	inline void SetState(MxU32 p_state) { m_state = p_state; }

	// SYNTHETIC: LEGO1 0x1000f3d0
	// JukeBoxState::`scalar deleting destructor'

protected:
	MxU32 m_state;  // 0x08
	MxU32 m_active; // 0x0c
};

#endif // JUKEBOXSTATE_H
