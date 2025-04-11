#include "mxdssound.h"

DECOMP_SIZE_ASSERT(MxDSSound, 0xc0)

// FUNCTION: LEGO1 0x100c92c0
// FUNCTION: BETA10 0x1015cfdb
MxDSSound::MxDSSound()
{
	m_type = e_sound;
	m_volume = 0x4f;
}

// FUNCTION: LEGO1 0x100c9470
// FUNCTION: BETA10 0x1015d060
MxDSSound::~MxDSSound()
{
}

// FUNCTION: LEGO1 0x100c94c0
// FUNCTION: BETA10 0x1015d0c8
void MxDSSound::CopyFrom(MxDSSound& p_dsSound)
{
	m_type = p_dsSound.m_type;
	m_volume = p_dsSound.m_volume;
}

// FUNCTION: BETA10 0x1015d100
MxDSSound::MxDSSound(MxDSSound& p_dsSound) : MxDSMediaAction(p_dsSound)
{
	CopyFrom(p_dsSound);
}

// FUNCTION: LEGO1 0x100c94e0
// FUNCTION: BETA10 0x1015d181
MxDSSound& MxDSSound::operator=(MxDSSound& p_dsSound)
{
	if (this == &p_dsSound) {
		return *this;
	}

	MxDSMediaAction::operator=(p_dsSound);
	CopyFrom(p_dsSound);
	return *this;
}

// FUNCTION: LEGO1 0x100c9510
// FUNCTION: BETA10 0x1015d1c8
MxDSAction* MxDSSound::Clone()
{
	MxDSSound* clone = new MxDSSound();

	if (clone) {
		*clone = *this;
	}

	return clone;
}

// FUNCTION: LEGO1 0x100c95a0
// FUNCTION: BETA10 0x1015d272
void MxDSSound::Deserialize(MxU8*& p_source, MxS16 p_unk0x24)
{
	MxDSMediaAction::Deserialize(p_source, p_unk0x24);
	m_volume = *(MxS32*) p_source;
	p_source += sizeof(m_volume);
}

// FUNCTION: LEGO1 0x100c95d0
// FUNCTION: BETA10 0x1015d2b0
MxU32 MxDSSound::GetSizeOnDisk()
{
	MxU32 totalSizeOnDisk = MxDSMediaAction::GetSizeOnDisk();
	totalSizeOnDisk += sizeof(m_volume);

	m_sizeOnDisk = sizeof(m_volume);
	return totalSizeOnDisk;
}
