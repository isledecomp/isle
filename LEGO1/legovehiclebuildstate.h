#ifndef LEGOVEHICLEBUILDSTATE_H
#define LEGOVEHICLEBUILDSTATE_H

#include "decomp.h"
#include "legostate.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d66e0
// SIZE 0x50 (from 1000acd7)
class LegoVehicleBuildState : public LegoState {
public:
	LegoVehicleBuildState(char* p_classType);

	// FUNCTION: LEGO1 0x10025ff0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		return this->m_className.GetData();
	}

	// FUNCTION: LEGO1 0x10026000
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, this->m_className.GetData()) || LegoState::IsA(p_name);
	}

public:
	struct UnkStruct {
		undefined4 m_unk0x00;
		undefined2 m_unk0x04;
		undefined2 m_unk0x06;
		undefined2 m_unk0x08;

		UnkStruct();
	};

private:
	UnkStruct m_unk0x08[4]; // 0x08

	// This can be one of the following:
	// * LegoRaceCarBuildState
	// * LegoCopterBuildState
	// * LegoDuneCarBuildState
	// * LegoJetskiBuildState
	MxString m_className; // 0x38

	// Known States:
	// * 1 == enter(ing) build screen
	// * 3 == cutscene/dialogue
	// * 6 == exit(ing) build screen
	MxU32 m_animationState; // 0x48
	undefined m_unk0x4c;    // 0x4c
	undefined m_unk0x4d;    // 0x4d
	undefined m_unk0x4e;    // 0x4e
	MxU8 m_placedPartCount; // 0x4f
};

#endif // LEGOVEHICLEBUILDSTATE_H
