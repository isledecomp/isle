#include "mxcompositemediapresenter.h"

#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "misc.h"
#include "mxautolocker.h"
#include "mxdsmultiaction.h"
#include "mxmediapresenter.h"
#include "mxmisc.h"
#include "mxobjectfactory.h"
#include "mxtimer.h"

DECOMP_SIZE_ASSERT(MxCompositeMediaPresenter, 0x50)

// FUNCTION: LEGO1 0x10073ea0
MxCompositeMediaPresenter::MxCompositeMediaPresenter()
{
	m_unk0x4c = 0;
	m_unk0x4e = FALSE;
	VideoManager()->RegisterPresenter(*this);
}

// FUNCTION: LEGO1 0x10074020
MxCompositeMediaPresenter::~MxCompositeMediaPresenter()
{
	VideoManager()->UnregisterPresenter(*this);
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
		cursor.Head();

		while (cursor.Current(action)) {
			MxBool success = FALSE;
			const char* presenterName;
			MxPresenter* presenter = NULL;

			cursor.Next();

			if (m_action->GetFlags() & MxDSAction::c_looping) {
				action->SetFlags(action->GetFlags() | MxDSAction::c_looping);
			}
			else if (m_action->GetFlags() & MxDSAction::c_bit3) {
				action->SetFlags(action->GetFlags() | MxDSAction::c_bit3);
			}

			presenterName = PresenterNameDispatch(*action);
			presenter = (MxPresenter*) ObjectFactory()->Create(presenterName);

			if (presenter && presenter->AddToManager() == SUCCESS) {
				presenter->SetCompositePresenter(this);
				if (presenter->StartAction(p_controller, action) == SUCCESS) {
					presenter->SetTickleState(e_idle);

					if (presenter->IsA("MxVideoPresenter")) {
						VideoManager()->UnregisterPresenter(*presenter);
					}
					else if (presenter->IsA("MxAudioPresenter")) {
						SoundManager()->UnregisterPresenter(*presenter);
					}

					success = TRUE;
				}
			}

			if (success) {
				action->SetOrigin(this);
				m_list.push_back(presenter);
			}
			else if (presenter) {
				delete presenter;
			}
		}

		if (!m_compositePresenter) {
			SetTickleState(e_ready);
			MxLong time = Timer()->GetTime();
			m_action->SetUnknown90(time);
		}

		result = SUCCESS;
	}

	return result;
}

// FUNCTION: LEGO1 0x100742e0
void MxCompositeMediaPresenter::StartingTickle()
{
	MxAutoLocker lock(&m_criticalSection);

	if (!m_unk0x4e) {
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if ((*it)->GetCurrentTickleState() < e_streaming) {
				(*it)->Tickle();

				if ((*it)->GetCurrentTickleState() == e_streaming ||
					((*it)->GetAction() && (*it)->GetAction()->GetStartTime())) {
					m_unk0x4c++;
				}
			}
		}

		if (m_list.size() == m_unk0x4c) {
			m_unk0x4e = TRUE;
			m_unk0x4c = 0;

			for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
				if (!(*it)->GetAction()->GetStartTime()) {
					m_unk0x4c++;
				}
			}
		}
	}
	else {
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			if (!(*it)->GetAction()->GetStartTime() && ((MxMediaPresenter*) *it)->CurrentChunk() &&
				!((*it)->GetAction()->GetFlags() & MxDSAction::c_bit9)) {
				(*it)->Tickle();
				(*it)->GetAction()->SetFlags((*it)->GetAction()->GetFlags() | MxDSAction::c_bit9);
				m_unk0x4c--;
			}
		}

		if (!m_unk0x4c) {
			ProgressTickleState(e_streaming);
			MxLong time = Timer()->GetTime();
			m_action->SetUnknown90(time);
		}
	}
}

// FUNCTION: LEGO1 0x10074470
MxResult MxCompositeMediaPresenter::Tickle()
{
	MxAutoLocker lock(&m_criticalSection);

	switch (m_currentTickleState) {
	case e_ready:
		ProgressTickleState(e_starting);
	case e_starting:
		StartingTickle();
		break;
	case e_streaming:
	case e_repeating:
	case e_unk5:
	case e_done: {
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			(*it)->Tickle();
		}
		break;
	}
	default:
		break;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x10074540
MxResult MxCompositeMediaPresenter::PutData()
{
	MxAutoLocker lock(&m_criticalSection);

	if (m_currentTickleState >= e_streaming && m_currentTickleState <= e_done) {
		for (MxCompositePresenterList::iterator it = m_list.begin(); it != m_list.end(); it++) {
			(*it)->PutData();
		}
	}

	return SUCCESS;
}
