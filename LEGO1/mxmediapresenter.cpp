#include "mxmediapresenter.h"

#include "mxactionnotificationparam.h"
#include "mxautolocker.h"
#include "mxcompositepresenter.h"
#include "mxnotificationmanager.h"
#include "mxstreamchunk.h"

DECOMP_SIZE_ASSERT(MxMediaPresenter, 0x50);

// OFFSET: LEGO1 0x1000c550
MxMediaPresenter::~MxMediaPresenter()
{
	Destroy(TRUE);
}

// OFFSET: LEGO1 0x1000c5b0
void MxMediaPresenter::Destroy()
{
	Destroy(FALSE);
}

// OFFSET: LEGO1 0x100b54e0
void MxMediaPresenter::Init()
{
	this->m_subscriber = NULL;
	this->m_chunks = NULL;
	this->m_cursor = NULL;
	this->m_currentChunk = NULL;
}

// OFFSET: LEGO1 0x100b54f0
void MxMediaPresenter::Destroy(MxBool p_fromDestructor)
{
	{
		MxAutoLocker lock(&m_criticalSection);

		if (m_currentChunk && m_subscriber)
			m_subscriber->FUN_100b8390(m_currentChunk);

		if (m_subscriber)
			delete m_subscriber;

		if (m_cursor)
			delete m_cursor;

		if (m_chunks) {
			MxStreamChunkListCursor cursor(m_chunks);
			MxStreamChunk* chunk;

			while (cursor.Next(chunk))
				if (chunk->m_unk18)
					delete[] chunk->m_unk18;

			delete m_chunks;
		}

		Init();
	}

	if (!p_fromDestructor)
		MxPresenter::Destroy();
}

// OFFSET: LEGO1 0x100b5d10 STUB
MxResult MxMediaPresenter::Tickle()
{
	// TODO
	return SUCCESS;
}

// OFFSET: LEGO1 0x100b5d90 STUB
void MxMediaPresenter::StreamingTickle()
{
	// TODO
}

// OFFSET: LEGO1 0x100b5e10 STUB
void MxMediaPresenter::RepeatingTickle()
{
	// TODO
}

// OFFSET: LEGO1 0x100b5ef0
void MxMediaPresenter::DoneTickle()
{
	m_previousTickleStates |= 1 << m_currentTickleState;
	m_currentTickleState = TickleState_Idle;
	EndAction();
}

// OFFSET: LEGO1 0x100b6030 STUB
void MxMediaPresenter::Enable(MxBool p_enable)
{
	// TODO
}

// OFFSET: LEGO1 0x100b5700
MxResult MxMediaPresenter::StartAction(MxStreamController* p_controller, MxDSAction* p_action)
{
	MxResult result = FAILURE;
	MxAutoLocker lock(&m_criticalSection);

	if (MxPresenter::StartAction(p_controller, p_action) == SUCCESS) {
		if (m_action->GetFlags() & MxDSAction::Flag_Looping) {
			m_chunks = new MxStreamChunkList;
			m_cursor = new MxStreamChunkListCursor(m_chunks);

			if (!m_chunks && !m_cursor)
				goto done;
		}

		if (p_controller) {
			m_subscriber = new MxDSSubscriber;

			if (!m_subscriber ||
				m_subscriber->FUN_100b7ed0(p_controller, p_action->GetObjectId(), p_action->GetUnknown24()) != SUCCESS)
				goto done;
		}

		result = SUCCESS;
	}

done:
	return result;
}

// OFFSET: LEGO1 0x100b5bc0
void MxMediaPresenter::EndAction()
{
	MxAutoLocker lock(&m_criticalSection);

	if (!m_action)
		return;

	m_currentChunk = NULL;

	if (m_action->GetFlags() & MxDSAction::Flag_World &&
		(!m_compositePresenter || !m_compositePresenter->VTable0x64(2))) {
		MxPresenter::Enable(FALSE);
		SetTickleState(TickleState_Idle);
	}
	else {
		MxDSAction* action = m_action;
		MxPresenter::EndAction();

		if (m_subscriber) {
			delete m_subscriber;
			m_subscriber = NULL;
		}

		if (action && action->GetUnknown8c()) {
			NotificationManager()->Send(
				action->GetUnknown8c(),
				&MxEndActionNotificationParam(c_notificationEndAction, this, action, FALSE)
			);
		}
	}
}

// OFFSET: LEGO1 0x100b5f10 STUB
void MxMediaPresenter::VTable0x58()
{
	// TODO
}
