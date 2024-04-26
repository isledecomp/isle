#ifndef AMBULANCEMISSIONSTATE_H
#define AMBULANCEMISSIONSTATE_H

#include "legostate.h"

// VTABLE: LEGO1 0x100d72a0
// SIZE 0x24
class AmbulanceMissionState : public LegoState {
public:
	AmbulanceMissionState();

	// FUNCTION: LEGO1 0x10037600
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f00e8
		return "AmbulanceMissionState";
	}

	// FUNCTION: LEGO1 0x10037610
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, AmbulanceMissionState::ClassName()) || LegoState::IsA(p_name);
	}

	MxResult Serialize(LegoFile* p_legoFile) override; // vtable+0x1c

	inline void SetUnknown0x08(undefined4 p_unk0x08) { m_unk0x08 = p_unk0x08; }

	inline MxU16 GetScore(MxU8 p_id)
	{
		switch (p_id) {
		case 1:
			return m_score1;
		case 2:
			return m_score2;
		case 3:
			return m_score3;
		case 4:
			return m_score4;
		case 5:
			return m_score5;
		default:
			return 0;
		}
	}

	// SYNTHETIC: LEGO1 0x100376c0
	// AmbulanceMissionState::`scalar deleting destructor'

protected:
	undefined4 m_unk0x08; // 0x08
	undefined4 m_unk0x0c; // 0x0c
	MxU16 m_unk0x10;      // 0x10
	MxU16 m_unk0x12;      // 0x12
	MxU16 m_unk0x14;      // 0x14
	MxU16 m_unk0x16;      // 0x16
	MxU16 m_unk0x18;      // 0x18
	MxU16 m_score1;       // 0x1a
	MxU16 m_score2;       // 0x1c
	MxU16 m_score3;       // 0x1e
	MxU16 m_score4;       // 0x20
	MxU16 m_score5;       // 0x22
};

#endif // AMBULANCEMISSIONSTATE_H
