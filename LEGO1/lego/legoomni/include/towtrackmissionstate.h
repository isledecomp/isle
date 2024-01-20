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
	virtual MxResult VTable0x1c(LegoFileStream* p_legoFileStream) override; // vtable+0x1C

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

	// SYNTHETIC: LEGO1 0x1004e060
	// TowTrackMissionState::`scalar deleting destructor'

protected:
	undefined4 m_unk0x08; // 0x08
	undefined4 m_unk0x0c; // 0x0c
	MxU8 m_unk0x10;       // 0x10
	MxU16 m_unk0x12;      // 0x12
	MxU16 m_unk0x14;      // 0x14
	MxU16 m_unk0x16;      // 0x16
	MxU16 m_unk0x18;      // 0x18
	MxU16 m_unk0x1a;      // 0x1a
	MxU16 m_unk0x1c;      // 0x1c
	MxU16 m_color1;       // 0x1e
	MxU16 m_color2;       // 0x20
	MxU16 m_color3;       // 0x22
	MxU16 m_color4;       // 0x24
	MxU16 m_color5;       // 0x26
};

#endif // TOWTRACKMISSIONSTATE_H
