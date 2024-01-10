#ifndef RACECAR_H
#define RACECAR_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d6918
// SIZE 0x164
class RaceCar : public IslePathActor {
public:
	RaceCar();
	virtual ~RaceCar() override; // vtable+0x0

	// FUNCTION: LEGO1 0x10028270
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03e0
		return "RaceCar";
	}

	// FUNCTION: LEGO1 0x10028280
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, RaceCar::ClassName()) || IslePathActor::IsA(p_name);
	}

private:
	// TODO: RaceCar fields
	undefined m_unk0x160[4];
};

#endif // RACECAR_H
