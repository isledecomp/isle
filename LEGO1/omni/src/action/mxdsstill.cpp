#include "mxdsstill.h"

DECOMP_SIZE_ASSERT(MxDSStill, 0xb8)

// FUNCTION: LEGO1 0x100c98c0
MxDSStill::MxDSStill()
{
	this->SetType(e_still);
}

// FUNCTION: LEGO1 0x100c9a70
MxDSStill::~MxDSStill()
{
}

// FUNCTION: LEGO1 0x100c9ac0
void MxDSStill::CopyFrom(MxDSStill& p_dsStill)
{
}

// FUNCTION: LEGO1 0x100c9ad0
MxDSStill& MxDSStill::operator=(MxDSStill& p_dsStill)
{
	if (this == &p_dsStill) {
		return *this;
	}

	MxDSMediaAction::operator=(p_dsStill);
	this->CopyFrom(p_dsStill);
	return *this;
}

// FUNCTION: LEGO1 0x100c9b00
MxDSAction* MxDSStill::Clone()
{
	MxDSStill* clone = new MxDSStill();

	if (clone) {
		*clone = *this;
	}

	return clone;
}
