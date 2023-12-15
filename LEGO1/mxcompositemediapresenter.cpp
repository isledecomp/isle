#include "mxcompositemediapresenter.h"

#include "legoomni.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "mxautolocker.h"
#include "mxdsmultiaction.h"
#include "mxobjectfactory.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(MxCompositeMediaPresenter, 0x50)

// FUNCTION: LEGO1 0x10073ea0
MxCompositeMediaPresenter::MxCompositeMediaPresenter()
{
	m_unk0x4c = 0;
	m_unk0x4e = 0;
	VideoManager()->AddPresenter(*this);
}

// FUNCTION: LEGO1 0x10074020
MxCompositeMediaPresenter::~MxCompositeMediaPresenter()
{
	VideoManager()->RemovePresenter(*this);
}

// FUNCTION: LEGO1 0x10074090
MxResult MxCompositeMediaPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxAutoLocker lock(&m_criticalSection);

	MxResult result = FAILURE;
	MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
	MxDSActionListCursor cursor(actions);
	MxDSAction* action;

	if (MxPresenter::StartAction(p_controller, p_action) == SUCCESS) {
		// The usual cursor.Next() loop doesn't match here, even though
		// the logic is the same. It does match when "deconstructed" into
		// the following Head(), Current() and NextFragment() calls,
		// but this seems unlikely to be the original code.
		// The alpha debug build also uses Next().
		// cursor.Head();
		// while (cursor.Current(action)) {
		// cursor.NextFragment();
		while (cursor.Next(action)) {
			MxBool success = FALSE;

			action->CopyFlags(m_action->GetFlags());

			const char* presenterName = PresenterNameDispatch(*action);
			MxPresenter* presenter = (MxPresenter*) ObjectFactory()->Create(presenterName);

			if (presenter && presenter->AddToManager() == SUCCESS) {
				presenter->SetCompositePresenter(this);
				if (presenter->StartAction(p_controller, action) == SUCCESS) {
					presenter->SetTickleState(TickleState_Idle);

					if (presenter->IsA("MxVideoPresenter"))
						VideoManager()->RemovePresenter(*presenter);
					else if (presenter->IsA("MxAudioPresenter"))
						SoundManager()->RemovePresenter(*presenter);

					success = TRUE;
				}
			}

			if (success) {
				action->SetOrigin(this);
				m_list.push_back(presenter);
			}
			else if (presenter)
				delete presenter;
		}

		if (!m_compositePresenter) {
			SetTickleState(TickleState_Ready);
			MxLong time = Timer()->GetTime();
			m_action->SetUnknown90(time);
		}

		result = SUCCESS;
	}

	return result;
}

// STUB: LEGO1 0x100742e0
void MxCompositeMediaPresenter::StartingTickle()
{
	// TODO
}

// STUB: LEGO1 0x10074470
MxResult MxCompositeMediaPresenter::Tickle()
{
	// TODO
	return SUCCESS;
}

// STUB: LEGO1 0x10074540
MxResult MxCompositeMediaPresenter::PutData()
{
	// TODO
	return SUCCESS;
}
