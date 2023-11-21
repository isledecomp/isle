#include "mxdssound.h"

#include "legoutil.h"

DECOMP_SIZE_ASSERT(MxDSSound, 0xc0)

// OFFSET: LEGO1 0x100c92c0
MxDSSound::MxDSSound()
{
	this->m_volume = 0x4f;
	this->SetType(MxDSType_Sound);
}

// OFFSET: LEGO1 0x100c9470
MxDSSound::~MxDSSound()
{
}

// OFFSET: LEGO1 0x100c94c0
void MxDSSound::CopyFrom(MxDSSound& p_dsSound)
{
	this->SetType(p_dsSound.GetType());
	this->m_volume = p_dsSound.m_volume;
}

// OFFSET: LEGO1 0x100c94e0
MxDSSound& MxDSSound::operator=(MxDSSound& p_dsSound)
{
	if (this == &p_dsSound)
		return *this;

	MxDSMediaAction::operator=(p_dsSound);
	this->CopyFrom(p_dsSound);
	return *this;
}

// OFFSET: LEGO1 0x100c9510
MxDSAction* MxDSSound::Clone()
{
	MxDSSound* clone = new MxDSSound();

	if (clone)
		*clone = *this;

	return clone;
}

// OFFSET: LEGO1 0x100c95a0
void MxDSSound::Deserialize(char** p_source, MxS16 p_unk24)
{
	MxDSMediaAction::Deserialize(p_source, p_unk24);

	GetScalar(p_source, this->m_volume);
}

// OFFSET: LEGO1 0x100c95d0
MxU32 MxDSSound::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk = MxDSMediaAction::GetSizeOnDisk();

	this->m_sizeOnDisk = sizeof(this->m_volume);
	return totalSizeOnDisk + 4;
}
