#include "mxdsstill.h"

DECOMP_SIZE_ASSERT(MxDSStill, 0xb8)

// FUNCTION: LEGO1 0x100c98c0
// FUNCTION: BETA10 0x1015d54f
MxDSStill::MxDSStill()
{
	m_type = e_still;
}

// FUNCTION: LEGO1 0x100c9a70
// FUNCTION: BETA10 0x1015d5c7
MxDSStill::~MxDSStill()
{
}

// FUNCTION: LEGO1 0x100c9ac0
// FUNCTION: BETA10 0x1015d62f
void MxDSStill::CopyFrom(MxDSStill& p_dsStill)
{
}

// FUNCTION: BETA10 0x1015d647
MxDSStill::MxDSStill(MxDSStill& p_dsStill) : MxDSMediaAction(p_dsStill)
{
	CopyFrom(p_dsStill);
}

// FUNCTION: LEGO1 0x100c9ad0
// FUNCTION: BETA10 0x1015d6c8
MxDSStill& MxDSStill::operator=(MxDSStill& p_dsStill)
{
	if (this == &p_dsStill) {
		return *this;
	}

	MxDSMediaAction::operator=(p_dsStill);
	CopyFrom(p_dsStill);
	return *this;
}

// FUNCTION: LEGO1 0x100c9b00
// FUNCTION: BETA10 0x1015d70f
MxDSAction* MxDSStill::Clone()
{
	MxDSStill* clone = new MxDSStill();

	if (clone) {
		*clone = *this;
	}

	return clone;
}
