#include "legoanimmmpresenter.h"

#include "decomp.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxautolock.h"
#include "mxdsmultiaction.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"

DECOMP_SIZE_ASSERT(LegoAnimMMPresenter, 0x74)

// FUNCTION: LEGO1 0x1004a8d0
LegoAnimMMPresenter::LegoAnimMMPresenter()
{
	m_unk0x4c = NULL;
	m_unk0x5c = 0;
	m_unk0x59 = 0;
	m_unk0x60 = 0;
	m_unk0x54 = 0;
	m_unk0x64 = NULL;
	m_unk0x68 = 0;
	m_unk0x6c = 0;
	m_unk0x70 = 0;
	m_unk0x58 = 0;
}

// FUNCTION: LEGO1 0x1004aaf0
MxResult LegoAnimMMPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	AUTOLOCK(m_criticalSection);

	MxResult result = FAILURE;
	MxDSActionList* actions = ((MxDSMultiAction*) p_action)->GetActionList();
	MxObjectFactory* factory = ObjectFactory();
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
			presenter = (MxPresenter*) factory->Create(presenterName);

			if (presenter && presenter->AddToManager() == SUCCESS) {
				presenter->SetCompositePresenter(this);
				if (presenter->StartAction(p_controller, action) == SUCCESS) {
					presenter->SetTickleState(MxPresenter::e_idle);

					if (presenter->IsA("LegoAnimPresenter") || presenter->IsA("LegoLoopingAnimPresenter")) {
						m_unk0x4c = presenter;
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

		m_unk0x64 = CurrentWorld();
		if (m_unk0x64) {
			m_unk0x64->Add(this);
		}
		VideoManager()->RegisterPresenter(*this);

		result = SUCCESS;
	}

	return result;
}

// STUB: LEGO1 0x1004aec0
void LegoAnimMMPresenter::EndAction()
{
	// TODO
}

// STUB: LEGO1 0x1004b140
void LegoAnimMMPresenter::ReadyTickle()
{
	// TODO
}

// STUB: LEGO1 0x1004b1c0
void LegoAnimMMPresenter::StartingTickle()
{
	// TODO
}

// STUB: LEGO1 0x1004b220
void LegoAnimMMPresenter::StreamingTickle()
{
	// TODO
}

// STUB: LEGO1 0x1004b250
void LegoAnimMMPresenter::RepeatingTickle()
{
	// TODO
}

// FUNCTION: LEGO1 0x1004b2c0
void LegoAnimMMPresenter::DoneTickle()
{
	// Empty
}

// STUB: LEGO1 0x1004b2d0
MxLong LegoAnimMMPresenter::Notify(MxParam& p_param)
{
	// TODO
	return 0;
}

// FUNCTION: LEGO1 0x1004b360
void LegoAnimMMPresenter::VTable0x60(MxPresenter* p_presenter)
{
	if (m_unk0x4c == p_presenter && ((MxU8) p_presenter->GetCurrentTickleState() == MxPresenter::e_streaming ||
									 (MxU8) p_presenter->GetCurrentTickleState() == MxPresenter::e_done)) {
		p_presenter->SetTickleState(MxPresenter::e_idle);
	}
}

// STUB: LEGO1 0x1004b390
void LegoAnimMMPresenter::ParseExtra()
{
	// TODO
}

// STUB: LEGO1 0x1004b8b0
MxBool LegoAnimMMPresenter::FUN_1004b8b0()
{
	// TODO
	return FALSE;
}
