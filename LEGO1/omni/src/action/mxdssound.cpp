#include "mxdssound.h"

#include "mxutil.h"

DECOMP_SIZE_ASSERT(MxDSSound, 0xc0)

// FUNCTION: LEGO1 0x100c92c0
MxDSSound::MxDSSound()
{
	this->m_volume = 0x4f;
	this->SetType(e_sound);
}

// FUNCTION: LEGO1 0x100c9470
MxDSSound::~MxDSSound()
{
}

// FUNCTION: LEGO1 0x100c94c0
void MxDSSound::CopyFrom(MxDSSound& p_dsSound)
{
	this->SetType(p_dsSound.GetType());
	this->m_volume = p_dsSound.m_volume;
}

// FUNCTION: LEGO1 0x100c94e0
MxDSSound& MxDSSound::operator=(MxDSSound& p_dsSound)
{
	if (this == &p_dsSound)
		return *this;

	MxDSMediaAction::operator=(p_dsSound);
	this->CopyFrom(p_dsSound);
	return *this;
}

// FUNCTION: LEGO1 0x100c9510
MxDSAction* MxDSSound::Clone()
{
	MxDSSound* clone = new MxDSSound();

	if (clone)
		*clone = *this;

	return clone;
}

// FUNCTION: LEGO1 0x100c95a0
void MxDSSound::Deserialize(MxU8** p_source, MxS16 p_unk0x24)
{
	MxDSMediaAction::Deserialize(p_source, p_unk0x24);

	GetScalar(p_source, this->m_volume);
}

// FUNCTION: LEGO1 0x100c95d0
MxU32 MxDSSound::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk = MxDSMediaAction::GetSizeOnDisk();

	this->m_sizeOnDisk = sizeof(this->m_volume);
	return totalSizeOnDisk + 4;
}
