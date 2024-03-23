#ifndef LEGOANIMACTOR_H
#define LEGOANIMACTOR_H

#include "decomp.h"
#include "legopathactor.h"

/*
	VTABLE: LEGO1 0x100d5440 LegoPathActor
	VTABLE: LEGO1 0x100d5510 LegoAnimActor
*/
// SIZE 0x174
class LegoAnimActor : public virtual LegoPathActor {
public:
	LegoAnimActor() { m_index = -1; }

	// FUNCTION: LEGO1 0x1000fb90
	inline const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f057c
		return "LegoAnimActor";
	}

	// FUNCTION: LEGO1 0x1000fbb0
	inline MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, LegoAnimActor::ClassName()) || LegoPathActor::IsA(p_name);
	}

	virtual MxResult FUN_1001c1f0(float& p_out);
	virtual MxResult FUN_1001c360(float, undefined4);
	virtual MxResult FUN_1001c450(undefined4, undefined4, undefined4, undefined4);
	virtual void FUN_1001c800();

	// SYNTHETIC: LEGO1 0x1000fb50
	// LegoAnimActor::`scalar deleting destructor'

private:
	vector<void*> m_unk0x08; // 0x08
	MxU16 m_index;           // 0x18
};

#endif // LEGOANIMACTOR_H
