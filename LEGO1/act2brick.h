#ifndef ACT2BRICK_H
#define ACT2BRICK_H

#include "legopathactor.h"

// VTABLE: LEGO1 0x100d9b60
// SIZE 0x194
class Act2Brick : public LegoPathActor {
public:
	Act2Brick();
	virtual ~Act2Brick() override; // vtable+0x0

	virtual MxLong Notify(MxParam& p_param) override; // vtable+0x4
	virtual MxResult Tickle() override;               // vtable+0x08

	// FUNCTION: LEGO1 0x1007a360
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f0438
		return "Act2Brick";
	}

	// FUNCTION: LEGO1 0x1007a370
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act2Brick::ClassName()) || LegoEntity::IsA(p_name);
	}
};

#endif // ACT2BRICK_H
