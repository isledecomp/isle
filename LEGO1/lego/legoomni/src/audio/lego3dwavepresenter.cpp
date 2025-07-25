#include "lego3dwavepresenter.h"

#include "mxcompositepresenter.h"
#include "mxdsaction.h"
#include "mxmain.h"

DECOMP_SIZE_ASSERT(Lego3DWavePresenter, 0xa0)

// FUNCTION: LEGO1 0x1004a7c0
MxResult Lego3DWavePresenter::AddToManager()
{
	MxResult result = MxWavePresenter::AddToManager();
	MxWavePresenter::Init();

	if (MxOmni::IsSound3D()) {
		m_is3d = TRUE;
	}

	return result;
}

// FUNCTION: LEGO1 0x1004a7f0
void Lego3DWavePresenter::Destroy()
{
	MxWavePresenter::Destroy();
	MxWavePresenter::Init();

	if (MxOmni::IsSound3D()) {
		m_is3d = TRUE;
	}
}

// FUNCTION: LEGO1 0x1004a810
// FUNCTION: BETA10 0x1003a3b0
void Lego3DWavePresenter::StartingTickle()
{
	if (MxOmni::IsSound3D()) {
		m_is3d = TRUE;
	}

	MxWavePresenter::StartingTickle();

	if (m_dsBuffer != NULL) {
		MxU16 extraLength;
		char* buff;
		m_action->GetExtra(extraLength, buff);

		if (!strcmp(buff, "FROM_PARENT") && m_compositePresenter != NULL) {
			m_compositePresenter->GetAction()->GetExtra(extraLength, buff);
		}

		if (m_sound.Create(m_dsBuffer, buff, m_volume) != SUCCESS) {
			m_dsBuffer->Release();
			m_dsBuffer = NULL;
			EndAction();
		}
	}
}

// FUNCTION: LEGO1 0x1004a8b0
// FUNCTION: BETA10 0x1003a4cc
void Lego3DWavePresenter::StreamingTickle()
{
	MxWavePresenter::StreamingTickle();
	m_sound.UpdatePosition(m_dsBuffer);
}
