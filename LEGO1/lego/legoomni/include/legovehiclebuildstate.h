#ifndef LEGOVEHICLEBUILDSTATE_H
#define LEGOVEHICLEBUILDSTATE_H

#include "decomp.h"
#include "legostate.h"
#include "mxstring.h"

// VTABLE: LEGO1 0x100d66e0
// SIZE 0x50
class LegoVehicleBuildState : public LegoState {
public:
	LegoVehicleBuildState(char* p_classType);

	// FUNCTION: LEGO1 0x10025ff0
	inline const char* ClassName() const override // vtable+0x0c
	{
		return this->m_className.GetData();
	}

	// FUNCTION: LEGO1 0x10026000
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, this->m_className.GetData()) || LegoState::IsA(p_name);
	}

	MxResult VTable0x1c(LegoFile* p_legoFile) override; // vtable+0x1c

	// SYNTHETIC: LEGO1 0x100260a0
	// LegoVehicleBuildState::`scalar deleting destructor'

private:
	Playlist m_unk0x08[4]; // 0x08

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
