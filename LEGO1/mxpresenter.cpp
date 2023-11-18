#include "mxpresenter.h"

#include "decomp.h"
#include "define.h"
#include "legoomni.h"
#include "mxactionnotificationparam.h"
#include "mxautolocker.h"
#include "mxcompositepresenter.h"
#include "mxdsanim.h"
#include "mxdssound.h"
#include "mxnotificationmanager.h"
#include "mxparam.h"
#include "mxstreamer.h"

#include <string.h>

DECOMP_SIZE_ASSERT(MxPresenter, 0x40);

// OFFSET: LEGO1 0x100b4d50
void MxPresenter::Init()
{
	m_currentTickleState = TickleState_Idle;
	m_action = NULL;
	m_location = MxPoint32(0, 0);
	m_displayZ = 0;
	m_compositePresenter = NULL;
	m_previousTickleStates = 0;
}

// OFFSET: LEGO1 0x100b4fc0
void MxPresenter::ParseExtra()
{
	MxAutoLocker lock(&m_criticalSection);
	MxU16 len = m_action->GetExtraLength();
	char* extraData = m_action->GetExtraData();

	if (len) {
		// len &= MAXWORD;
		char extraCopy[512];
		memcpy(extraCopy, extraData, len);
		extraCopy[len] = '\0';

		char t_worldValue[512];
		if (KeyValueStringParse(t_worldValue, g_strWORLD, extraCopy)) {
			char* token = strtok(t_worldValue, g_parseExtraTokens);
			char t_token[256];
			strcpy(t_token, token);

			token = strtok(NULL, g_parseExtraTokens);
			MxS32 val = token ? atoi(token) : 0;
			MxEntity* result = MxOmni::GetInstance()->FindWorld(t_token, val, this);

			m_action->SetFlags(m_action->GetFlags() | MxDSAction::Flag_World);

			if (result)
				SendToCompositePresenter(MxOmni::GetInstance());
		}
	}
}

// OFFSET: LEGO1 0x100b5120
void MxPresenter::SendToCompositePresenter(MxOmni* p_omni)
{
	if (m_compositePresenter) {
		MxAutoLocker lock(&m_criticalSection);

		NotificationManager()->Send(m_compositePresenter, &MxNotificationParam(MXPRESENTER_NOTIFICATION, this));

		m_action->SetUnknown8c(p_omni ? p_omni : MxOmni::GetInstance());
		m_compositePresenter = NULL;
	}
}

// OFFSET: LEGO1 0x1000bf00
MxPresenter::~MxPresenter()
{
}

// OFFSET: LEGO1 0x100b5200
MxResult MxPresenter::Tickle()
{
	MxAutoLocker lock(&this->m_criticalSection);

	switch (this->m_currentTickleState) {
	case TickleState_Ready:
		this->ReadyTickle();

		if (m_currentTickleState != TickleState_Starting)
			break;
	case TickleState_Starting:
		this->StartingTickle();

		if (m_currentTickleState != TickleState_Streaming)
			break;
	case TickleState_Streaming:
		this->StreamingTickle();

		if (m_currentTickleState != TickleState_Repeating)
			break;
	case TickleState_Repeating:
		this->RepeatingTickle();

		if (m_currentTickleState != TickleState_unk5)
			break;
	case TickleState_unk5:
		this->Unk5Tickle();

		if (m_currentTickleState != TickleState_Done)
			break;
	case TickleState_Done:
		this->DoneTickle();
	default:
		break;
	}

	return SUCCESS;
}

// OFFSET: LEGO1 0x100b4d80
MxResult MxPresenter::StartAction(MxStreamController*, MxDSAction* p_action)
{
	MxAutoLocker lock(&this->m_criticalSection);

	this->m_action = p_action;

	const Vector3Data& location = this->m_action->GetLocation();
	MxS32 previousTickleState = this->m_currentTickleState;

	this->m_location = MxPoint32(this->m_action->GetLocation()[0], this->m_action->GetLocation()[1]);
	this->m_displayZ = this->m_action->GetLocation()[2];
	this->m_previousTickleStates |= 1 << (unsigned char) previousTickleState;
	this->m_currentTickleState = TickleState_Ready;

	return SUCCESS;
}

// OFFSET: LEGO1 0x100b4e40
void MxPresenter::EndAction()
{
	if (this->m_action == FALSE)
		return;

	MxAutoLocker lock(&this->m_criticalSection);

	if (!this->m_compositePresenter) {
		MxOmni::GetInstance()->NotifyCurrentEntity(
			&MxEndActionNotificationParam(c_notificationEndAction, NULL, this->m_action, TRUE)
		);
	}

	this->m_action = FALSE;
	MxS32 previousTickleState = 1 << m_currentTickleState;
	this->m_previousTickleStates |= previousTickleState;
	this->m_currentTickleState = TickleState_Idle;
}

// OFFSET: LEGO1 0x100b52d0
void MxPresenter::Enable(MxBool p_enable)
{
	if (this->m_action && this->IsEnabled() != p_enable) {
		MxU32 flags = this->m_action->GetFlags();

		if (p_enable)
			this->m_action->SetFlags(flags | MxDSAction::Flag_Enabled);
		else
			this->m_action->SetFlags(flags & ~MxDSAction::Flag_Enabled);
	}
}

// OFFSET: LEGO1 0x100b5310
const char* PresenterNameDispatch(const MxDSAction& p_action)
{
	const char* name = p_action.GetSourceName();
	MxS32 format;

	if (!name || strlen(name) == 0) {
		switch (p_action.GetType()) {
		case MxDSType_Anim:
			format = ((MxDSAnim&) p_action).GetMediaFormat();
			switch (format) {
			case FOURCC(' ', 'F', 'L', 'C'):
				name = !p_action.IsLooping() ? "MxFlcPresenter" : "MxLoopingFlcPresenter";
				break;
			case FOURCC(' ', 'S', 'M', 'K'):
				name = !p_action.IsLooping() ? "MxSmkPresenter" : "MxLoopingSmkPresenter";
				break;
			}
			break;

		case MxDSType_Sound:
			format = ((MxDSSound&) p_action).GetMediaFormat();
			switch (format) {
			case FOURCC(' ', 'M', 'I', 'D'):
				name = !p_action.IsLooping() ? "MxMIDIPresenter" : "MxLoopingMIDIPresenter";
				break;
			case FOURCC(' ', 'W', 'A', 'V'):
				name = "MxWavePresenter";
				break;
			}
			break;

		case MxDSType_SerialAction:
		case MxDSType_ParallelAction:
		case MxDSType_SelectAction:
			name = "MxCompositePresenter";
			break;

		case MxDSType_Event:
			name = "MxEventPresenter";
			break;

		case MxDSType_Still:
			name = "MxStillPresenter";
			break;
		}
	}

	return name;
}

// OFFSET: LEGO1 0x100b54c0
MxBool MxPresenter::IsEnabled()
{
	return this->m_action && this->m_action->GetFlags() & MxDSAction::Flag_Enabled;
}

// OFFSET: LEGO1 0x1000be30
void MxPresenter::VTable0x14()
{
}

// OFFSET: LEGO1 0x1000be40
void MxPresenter::ReadyTickle()
{
	ParseExtra();

	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_Starting;
}

// OFFSET: LEGO1 0x1000be60
void MxPresenter::StartingTickle()
{
	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_Streaming;
}

// OFFSET: LEGO1 0x1000be80
void MxPresenter::StreamingTickle()
{
	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_Repeating;
}

// OFFSET: LEGO1 0x1000bea0
void MxPresenter::RepeatingTickle()
{
	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_unk5;
}

// OFFSET: LEGO1 0x1000bec0
void MxPresenter::Unk5Tickle()
{
	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = TickleState_Done;
}

// OFFSET: LEGO1 0x1000bee0
void MxPresenter::DoneTickle()
{
	m_previousTickleStates |= 1 << m_currentTickleState;
	m_currentTickleState = TickleState_Idle;
}

// OFFSET: LEGO1 0x1000bf70
MxResult MxPresenter::AddToManager()
{
	return SUCCESS;
}

// OFFSET: LEGO1 0x1000bf80
void MxPresenter::Destroy()
{
	Init();
}

// OFFSET: LEGO1 0x1000bf90
void MxPresenter::SetTickleState(TickleState p_tickleState)
{
	m_previousTickleStates |= 1 << (unsigned char) m_currentTickleState;
	m_currentTickleState = p_tickleState;
}

// OFFSET: LEGO1 0x1000bfb0
MxBool MxPresenter::HasTickleStatePassed(TickleState p_tickleState)
{
	return m_previousTickleStates & (1 << (unsigned char) p_tickleState);
}

// OFFSET: LEGO1 0x1000bfc0
undefined4 MxPresenter::PutData()
{
	return 0;
}

// OFFSET: LEGO1 0x1000bfd0
MxBool MxPresenter::IsHit(MxS32 p_x, MxS32 p_y)
{
	return FALSE;
}
