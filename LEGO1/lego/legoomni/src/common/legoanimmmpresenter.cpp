#include "legoanimmmpresenter.h"

#include "decomp.h"
#include "define.h"
#include "legoanimationmanager.h"
#include "legotraninfo.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "misc.h"
#include "mxautolock.h"
#include "mxdsmultiaction.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxtimer.h"
#include "mxutilities.h"

DECOMP_SIZE_ASSERT(LegoAnimMMPresenter, 0x74)

// FUNCTION: LEGO1 0x1004a8d0
LegoAnimMMPresenter::LegoAnimMMPresenter()
{
	m_unk0x4c = NULL;
	m_animmanId = 0;
	m_unk0x59 = FALSE;
	m_tranInfo = NULL;
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
						m_unk0x4c = (LegoAnimPresenter*) presenter;
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

// FUNCTION: LEGO1 0x1004b140
// FUNCTION: BETA10 0x1004c197
void LegoAnimMMPresenter::ReadyTickle()
{
	ParseExtra();

	if (m_tranInfo != NULL && m_tranInfo->m_unk0x15 && m_tranInfo->m_unk0x1c != NULL &&
		m_tranInfo->m_unk0x1c[0] != NULL) {
		m_tranInfo->m_unk0x1c[0]->Enable(FALSE);
		m_tranInfo->m_unk0x1c[0]->Enable(TRUE);
	}

	if (m_tranInfo != NULL && m_tranInfo->m_unk0x0c != NULL) {
		m_unk0x4c->VTable0xa0(m_tranInfo->m_unk0x0c);
	}

	if (m_unk0x4c != NULL) {
		m_unk0x4c->SetTickleState(e_ready);
	}

	ProgressTickleState(e_starting);
}

// FUNCTION: LEGO1 0x1004b1c0
// FUNCTION: BETA10 0x1004c2cc
void LegoAnimMMPresenter::StartingTickle()
{
	if (m_unk0x4c == NULL || m_unk0x4c->GetCurrentTickleState() == e_idle) {
		if (m_tranInfo != NULL && m_tranInfo->m_unk0x08 != NULL) {
			m_unk0x4c->FUN_1006b140(m_tranInfo->m_unk0x08);
		}

		m_unk0x50 = Timer()->GetTime();
		ProgressTickleState(e_streaming);
	}
}

// FUNCTION: LEGO1 0x1004b220
// FUNCTION: BETA10 0x1004c372
void LegoAnimMMPresenter::StreamingTickle()
{
	if (FUN_1004b450()) {
		ProgressTickleState(e_repeating);
	}
}

// FUNCTION: LEGO1 0x1004b250
// FUNCTION: BETA10 0x1004c3a4
void LegoAnimMMPresenter::RepeatingTickle()
{
	if (m_unk0x4c == NULL) {
		ProgressTickleState(e_unk5);
	}
	else if (m_list.size() <= 1) {
		if (m_list.front() == m_unk0x4c) {
			m_unk0x4c->SetTickleState(e_done);
			ProgressTickleState(e_unk5);
		}
		else {
			ProgressTickleState(e_unk5);
		}
	}
}

// FUNCTION: LEGO1 0x1004b2c0
// FUNCTION: BETA10 0x1004c469
void LegoAnimMMPresenter::DoneTickle()
{
	// Empty
}

// FUNCTION: LEGO1 0x1004b2d0
// FUNCTION: BETA10 0x1004c47f
MxLong LegoAnimMMPresenter::Notify(MxParam& p_param)
{
	AUTOLOCK(m_criticalSection);

	if (((MxNotificationParam&) p_param).GetType() == c_notificationEndAction &&
		((MxNotificationParam&) p_param).GetSender() == m_unk0x4c) {
		m_unk0x4c = NULL;
	}

	return MxCompositePresenter::Notify(p_param);
}

// FUNCTION: LEGO1 0x1004b360
void LegoAnimMMPresenter::VTable0x60(MxPresenter* p_presenter)
{
	if (m_unk0x4c == p_presenter && ((MxU8) p_presenter->GetCurrentTickleState() == MxPresenter::e_streaming ||
									 (MxU8) p_presenter->GetCurrentTickleState() == MxPresenter::e_done)) {
		p_presenter->SetTickleState(MxPresenter::e_idle);
	}
}

// FUNCTION: LEGO1 0x1004b390
// FUNCTION: BETA10 0x1004c5be
void LegoAnimMMPresenter::ParseExtra()
{
	MxU16 extraLength;
	char* extraData;
	m_action->GetExtra(extraLength, extraData);

	if (extraLength & MAXWORD) {
		char extraCopy[1024];
		memcpy(extraCopy, extraData, extraLength & MAXWORD);
		extraCopy[extraLength & MAXWORD] = '\0';

		char output[1024];
		if (KeyValueStringParse(output, g_strANIMMAN_ID, extraCopy)) {
			char* token = strtok(output, g_parseExtraTokens);
			m_animmanId = atoi(token);
			m_tranInfo = AnimationManager()->GetTranInfo(m_animmanId);

			if (m_tranInfo != NULL) {
				m_unk0x59 = m_tranInfo->m_unk0x10;
				m_tranInfo->m_presenter = this;
			}
		}
	}
}

// STUB: LEGO1 0x1004b450
// FUNCTION: BETA10 0x1004c71d
MxBool LegoAnimMMPresenter::FUN_1004b450()
{
	// TODO
	return TRUE;
}

// FUNCTION: LEGO1 0x1004b8b0
// FUNCTION: BETA10 0x1004d104
MxBool LegoAnimMMPresenter::FUN_1004b8b0()
{
	return m_tranInfo != NULL ? m_tranInfo->m_unk0x28 : TRUE;
}
