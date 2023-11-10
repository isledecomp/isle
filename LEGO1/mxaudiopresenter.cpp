#include "mxaudiopresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxAudioPresenter, 0x54);

// OFFSET: LEGO1 0x1000d260
MxU32 MxAudioPresenter::GetVolume()
{
	return m_volume;
}

// OFFSET: LEGO1 0x1000d270
void MxAudioPresenter::SetVolume(MxU32 p_volume)
{
	m_volume = p_volume;
}
