#include "legopathpresenter.h"

#include "legoomni.h"
#include "legovideomanager.h"
#include "mxautolocker.h"

DECOMP_SIZE_ASSERT(LegoPathPresenter, 0x54);

// FUNCTION: LEGO1 0x100448d0
LegoPathPresenter::LegoPathPresenter()
{
	Init();
}

// FUNCTION: LEGO1 0x10044ab0
void LegoPathPresenter::Init()
{
}

// FUNCTION: LEGO1 0x10044b40
MxResult LegoPathPresenter::AddToManager()
{
	MxResult status = FAILURE;

	if (VideoManager()) {
		VideoManager()->AddPresenter(*this);
		status = SUCCESS;
	}

	return status;
}

// FUNCTION: LEGO1 0x10044b70
void LegoPathPresenter::Destroy(MxBool p_fromDestructor)
{
	if (VideoManager())
		VideoManager()->RemovePresenter(*this);

	{
		MxAutoLocker lock(&this->m_criticalSection);
		Init();
	}

	if (!p_fromDestructor)
		MxMediaPresenter::Destroy(FALSE);
}

// FUNCTION: LEGO1 0x10044c10
void LegoPathPresenter::Destroy()
{
	Destroy(FALSE);
}

// FUNCTION: LEGO1 0x10044d40
void LegoPathPresenter::RepeatingTickle()
{
	if (this->m_action->GetDuration() == -1)
		return;

	EndAction();
}

// STUB: LEGO1 0x10044d60
void LegoPathPresenter::ParseExtra()
{
	// TODO
}
