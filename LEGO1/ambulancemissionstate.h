#ifndef AMBULANCEMISSIONSTATE_H
#define AMBULANCEMISSIONSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d72a0
// SIZE 0x24
class AmbulanceMissionState : public LegoState {
public:
	AmbulanceMissionState();

	// FUNCTION: LEGO1 0x10037600
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f00e8
		return "AmbulanceMissionState";
	}

	// FUNCTION: LEGO1 0x10037610
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, AmbulanceMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	inline MxU16 GetColor(MxU8 id)
	{
		switch (id) {
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
	undefined m_unk0x8[0x12];
	MxU16 m_color1;
	MxU16 m_color2;
	MxU16 m_color3;
	MxU16 m_color4;
	MxU16 m_color5;
};

#endif // AMBULANCEMISSIONSTATE_H
