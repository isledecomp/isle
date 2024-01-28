#ifndef ACT3SHARK_H
#define ACT3SHARK_H

#include "legoanimactor.h"

// VTABLE: LEGO1 0x100d7920
class Act3Shark : public LegoAnimActor {
public:
	// FUNCTION: LEGO1 0x100430c0
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x100f03a0
		return "Act3Shark";
	}

	// FUNCTION: LEGO1 0x1001a130
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, Act3Shark::ClassName()) || LegoAnimActor::IsA(p_name);
	}

	virtual void ParseAction(char*) override;                  // vtable+0x20
	virtual void SetWorldSpeed(MxFloat p_worldSpeed) override; // vtable+0x30
	virtual void VTable0x70(float p_float) override;           // vtable+0x70
	virtual void VTable0x74(Matrix4& p_transform) override;    // vtable+0x74

	// SYNTHETIC: LEGO1 0x10043020
	// Act3Shark::`scalar deleting destructor'
};

#endif // ACT3SHARK_H
