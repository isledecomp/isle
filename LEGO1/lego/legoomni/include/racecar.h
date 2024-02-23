#ifndef RACECAR_H
#define RACECAR_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d6918
// SIZE 0x164
class RaceCar : public IslePathActor {
public:
	RaceCar();
	~RaceCar() override; // vtable+0x00

	// FUNCTION: LEGO1 0x10028270
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03e0
		return "RaceCar";
	}

	// FUNCTION: LEGO1 0x10028280
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceCar::ClassName()) || IslePathActor::IsA(p_name);
	}

	MxResult Create(MxDSAction& p_dsAction) override; // vtable+0x18
	MxU32 VTable0xcc() override;                      // vtable+0xcc

	// SYNTHETIC: LEGO1 0x10028400
	// RaceCar::`scalar deleting destructor'

private:
	// TODO: RaceCar fields
	undefined m_unk0x160[4];
};

#endif // RACECAR_H
