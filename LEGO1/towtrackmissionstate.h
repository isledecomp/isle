#ifndef TOWTRACKMISSIONSTATE_H
#define TOWTRACKMISSIONSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d7fd8
// SIZE 0x28
class TowTrackMissionState : public LegoState {
public:
	TowTrackMissionState();

	// FUNCTION: LEGO1 0x1004dfa0
	inline virtual const char* ClassName() const // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00bc
		return "TowTrackMissionState";
	}

	// FUNCTION: LEGO1 0x1004dfb0
	inline virtual MxBool IsA(const char* p_name) const // vtable+0x10
	{
		return !strcmp(p_name, TowTrackMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	inline MxU16 GetColor(MxU8 p_id)
	{
		switch (p_id) {
		case 1:
			return m_color1;
		case 2:
			return m_color2;
		case 3:
			return m_color3;
		case 4:
			return m_color4;
		case 5:
			return m_color5;
		default:
			return 0;
		}
	}

protected:
	undefined m_unk0x8[0x14];
	MxU16 m_color1;
	MxU16 m_color2;
	MxU16 m_color3;
	MxU16 m_color4;
	MxU16 m_color5;
};

#endif // TOWTRACKMISSIONSTATE_H
