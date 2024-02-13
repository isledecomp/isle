#include "lego3dwavepresenter.h"

#include "mxomni.h"

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

// STUB: LEGO1 0x1004a810
void Lego3DWavePresenter::StartingTickle()
{
	if (MxOmni::IsSound3D()) {
		m_is3d = TRUE;
	}

	MxWavePresenter::StartingTickle();

	// TODO
}

// STUB: LEGO1 0x1004a8b0
void Lego3DWavePresenter::StreamingTickle()
{
	MxWavePresenter::StreamingTickle();
	// TODO
}
