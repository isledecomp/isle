#ifndef HELICOPTER_H
#define HELICOPTER_H

#include "islepathactor.h"
#include "legostate.h"
#include "realtime/matrix.h"

// VTABLE: LEGO1 0x100d5418
// SIZE 0x0c
class HelicopterState : public LegoState {
public:
	// FUNCTION: LEGO1 0x1000e0d0
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0144
		return "HelicopterState";
	}

	// FUNCTION: LEGO1 0x1000e0e0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, HelicopterState::ClassName()) || LegoState::IsA(p_name);
	}

	// FUNCTION: LEGO1 0x1000e0b0
	MxBool IsSerializable() override { return FALSE; } // vtable+0x14

	// FUNCTION: LEGO1 0x1000e0c0
	MxBool SetFlag() override
	{
		m_unk0x08 = 0;
		return TRUE;
	} // vtable+0x18

	inline void SetUnknown8(MxU32 p_unk0x08) { m_unk0x08 = p_unk0x08; }
	inline MxU32 GetUnkown8() { return m_unk0x08; }

	// SYNTHETIC: LEGO1 0x1000e190
	// HelicopterState::`scalar deleting destructor'

	// TODO: Most likely getters/setters are not used according to BETA.

	MxU32 m_unk0x08; // 0x08
};

// VTABLE: LEGO1 0x100d40f8
// SIZE 0x230
class Helicopter : public IslePathActor {
public:
	Helicopter();
	~Helicopter() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10003070
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0130
		return "Helicopter";
	}

	// FUNCTION: LEGO1 0x10003080
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Helicopter::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override;                     // vtable+0x18
	void VTable0x70(float p_float) override;                              // vtable+0x70
	void VTable0x74(Matrix4& p_transform) override;                       // vtable+0x74
	MxLong HandleClick() override;                                        // vtable+0xcc
	MxLong HandleControl(LegoControlManagerEvent& p_param) override;      // vtable+0xd4
	MxLong HandleEndAnim(LegoEndAnimNotificationParam& p_param) override; // vtable+0xd8
	void Exit() override;                                                 // vtable+0xe4

	// SYNTHETIC: LEGO1 0x10003210
	// Helicopter::`scalar deleting destructor'

	void CreateState();

protected:
	MxMatrix m_unk0x160;              // 0x160
	MxMatrix m_unk0x1a8;              // 0x1a8
	float m_unk0x1f0;                 // 0x1f0
	UnknownMx4DPointFloat m_unk0x1f4; // 0x1f4
	HelicopterState* m_state;         // 0x228
	MxAtomId m_script;                // 0x22c
};

#endif // HELICOPTER_H
