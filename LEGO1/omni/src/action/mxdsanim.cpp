// Declaration-record carrier (dial campaign, PRE): samples this translation
// unit's accumulated declaration state before the include block. [14 units]
// Declaration-record carrier: the functions below sample the translation
// unit's accumulated declaration state (see the positional record calculus,
class MxUnkRecord000 {};
class MxUnkRecord001 {};
class MxUnkRecord002;
class MxUnkRecord003;
class MxUnkRecord004;

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
	if (&p_dsAnim == this) {
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
