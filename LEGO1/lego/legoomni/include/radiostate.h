#ifndef RADIOSTATE_H
#define RADIOSTATE_H

#include "legostate.h"
#include "mxdsaction.h"

// VTABLE: LEGO1 0x100d6d28
// SIZE 0x30
class RadioState : public LegoState {
public:
	RadioState();

	// FUNCTION: LEGO1 0x1002cf60
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f04f8
		return "RadioState";
	}

	// FUNCTION: LEGO1 0x1002cf70
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RadioState::ClassName()) || LegoState::IsA(p_name);
	}

	MxBool VTable0x14() override; // vtable+0x14

	// SYNTHETIC: LEGO1 0x1002d020
	// RadioState::`scalar deleting destructor'

	inline MxBool IsActive() { return m_active; }

	inline void SetActive(MxBool p_active) { m_active = p_active; }

	undefined4 FUN_1002d090();
	MxBool FUN_1002d0c0(const MxAtomId& p_atom, MxU32 p_objectId);

private:
	Playlist m_unk0x08[3]; // 0x08
	MxS16 m_unk0x2c;       // 0x2c
	MxBool m_active;       // 0x2e
};

#endif // RADIOSTATE_H
