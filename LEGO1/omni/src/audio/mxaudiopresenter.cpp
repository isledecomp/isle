#include "mxaudiopresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxAudioPresenter, 0x54);

// FUNCTION: LEGO1 0x1000d260
MxS32 MxAudioPresenter::GetVolume()
{
	return m_volume;
}

// FUNCTION: LEGO1 0x1000d270
void MxAudioPresenter::SetVolume(MxS32 p_volume)
{
	m_volume = p_volume;
}
