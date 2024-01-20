#ifndef MXDSANIM_H
#define MXDSANIM_H

#include "mxdsmediaaction.h"

// VTABLE: LEGO1 0x100dcd88
// SIZE 0xb8
class MxDSAnim : public MxDSMediaAction {
public:
	MxDSAnim();
	virtual ~MxDSAnim() override;

	void CopyFrom(MxDSAnim& p_dsAnim);
	MxDSAnim& operator=(MxDSAnim& p_dsAnim);

	// FUNCTION: LEGO1 0x100c9060
	inline virtual const char* ClassName() const override // vtable+0x0c
	{
		// STRING: LEGO1 0x101025d8
		return "MxDSAnim";
	}

	// FUNCTION: LEGO1 0x100c9070
	inline virtual MxBool IsA(const char* p_name) const override // vtable+0x10
	{
		return !strcmp(p_name, MxDSAnim::ClassName()) || MxDSMediaAction::IsA(p_name);
	}

	virtual MxDSAction* Clone() override; // vtable+2c;

	// SYNTHETIC: LEGO1 0x100c9180
	// MxDSAnim::`scalar deleting destructor'
};

#endif // MXDSANIM_H
