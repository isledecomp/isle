#ifndef JETSKI_H
#define JETSKI_H

#include "decomp.h"
#include "islepathactor.h"

// VTABLE: LEGO1 0x100d9ec8
// SIZE 0x164
class Jetski : public IslePathActor {
public:
	Jetski();

	// FUNCTION: LEGO1 0x1007e430
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// GLOBAL: LEGO1 0x100f03d8
		return "Jetski";
	}

	// FUNCTION: LEGO1 0x1007e440
	inline virtual MxBool IsA(const char* name) const override // vtable+0x10
	{
		return !strcmp(name, Jetski::ClassName()) || IslePathActor::IsA(name);
	}

private:
	// TODO: Jetski fields
	undefined m_unk160[4];
};

#endif // JETSKI_H
