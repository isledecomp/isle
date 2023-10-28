#include "mxdsanim.h"

DECOMP_SIZE_ASSERT(MxDSAnim, 0xb8)

// OFFSET: LEGO1 0x100c8ff0
MxDSAnim::MxDSAnim()
{
	this->SetType(MxDSType_Anim);
}

// OFFSET: LEGO1 0x100c91a0
MxDSAnim::~MxDSAnim()
{
}

// OFFSET: LEGO1 0x100c91f0
void MxDSAnim::CopyFrom(MxDSAnim& p_dsAnim)
{
}

// OFFSET: LEGO1 0x100c9200
MxDSAnim& MxDSAnim::operator=(MxDSAnim& p_dsAnim)
{
	if (this == &p_dsAnim)
		return *this;

	MxDSMediaAction::operator=(p_dsAnim);
	this->CopyFrom(p_dsAnim);
	return *this;
}

// OFFSET: LEGO1 0x100c9230
MxDSAction* MxDSAnim::Clone()
{
	MxDSAnim* clone = new MxDSAnim();

	if (clone)
		*clone = *this;

	return clone;
}
