#include "mxdsanim.h"

DECOMP_SIZE_ASSERT(MxDSAnim, 0xb8)

// FUNCTION: LEGO1 0x100c8ff0
// FUNCTION: BETA10 0x1015cd71
MxDSAnim::MxDSAnim()
{
	m_type = e_anim;
}

// FUNCTION: LEGO1 0x100c91a0
// FUNCTION: BETA10 0x1015cde9
MxDSAnim::~MxDSAnim()
{
}

// FUNCTION: LEGO1 0x100c91f0
// FUNCTION: BETA10 0x1015ce51
void MxDSAnim::CopyFrom(MxDSAnim& p_dsAnim)
{
}

// FUNCTION: BETA10 0x1015ce69
MxDSAnim::MxDSAnim(MxDSAnim& p_dsAnim) : MxDSMediaAction(p_dsAnim)
{
	CopyFrom(p_dsAnim);
}

// FUNCTION: LEGO1 0x100c9200
// FUNCTION: BETA10 0x1015ceea
MxDSAnim& MxDSAnim::operator=(MxDSAnim& p_dsAnim)
{
	if (this == &p_dsAnim) {
		return *this;
	}

	MxDSMediaAction::operator=(p_dsAnim);
	CopyFrom(p_dsAnim);
	return *this;
}

// FUNCTION: LEGO1 0x100c9230
// FUNCTION: BETA10 0x1015cf31
MxDSAction* MxDSAnim::Clone()
{
	MxDSAnim* clone = new MxDSAnim();

	if (clone) {
		*clone = *this;
	}

	return clone;
}
