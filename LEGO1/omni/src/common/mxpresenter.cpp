#include "mxpresenter.h"

#include "decomp.h"
#include "define.h"
#include "mxactionnotificationparam.h"
#include "mxautolocker.h"
#include "mxcompositepresenter.h"
#include "mxdsanim.h"
#include "mxdssound.h"
#include "mxentity.h"
#include "mxnotificationmanager.h"
#include "mxobjectfactory.h"
#include "mxparam.h"
#include "mxstreamer.h"
#include "mxutil.h"

#include <string.h>

DECOMP_SIZE_ASSERT(MxPresenter, 0x40);

// FUNCTION: LEGO1 0x100b4d50
void MxPresenter::Init()
{
	m_currentTickleState = e_idle;
	m_action = NULL;
	m_location = MxPoint32(0, 0);
	m_displayZ = 0;
	m_compositePresenter = NULL;
	m_previousTickleStates = 0;
}

// FUNCTION: LEGO1 0x100b4d80
MxResult MxPresenter::StartAction(MxStreamController*, MxDSAction* p_action)
{
	MxAutoLocker lock(&this->m_criticalSection);

	this->m_action = p_action;

	const Mx3DPointFloat& location = this->m_action->GetLocation();
	MxS32 previousTickleState = this->m_currentTickleState;

	this->m_location = MxPoint32(this->m_action->GetLocation()[0], this->m_action->GetLocation()[1]);
	this->m_displayZ = this->m_action->GetLocation()[2];
	ProgressTickleState(e_ready);

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b4e40
void MxPresenter::EndAction()
{
	if (this->m_action == NULL)
		return;

	MxAutoLocker lock(&this->m_criticalSection);

	if (!this->m_compositePresenter) {
#ifdef COMPAT_MODE
		{
			MxEndActionNotificationParam param(c_notificationEndAction, NULL, this->m_action, TRUE);
			MxOmni::GetInstance()->NotifyCurrentEntity(&param);
		}
#else
		MxOmni::GetInstance()->NotifyCurrentEntity(
			&MxEndActionNotificationParam(c_notificationEndAction, NULL, this->m_action, TRUE)
		);
#endif
	}

	this->m_action = NULL;
	MxS32 previousTickleState = 1 << m_currentTickleState;
	this->m_previousTickleStates |= previousTickleState;
	this->m_currentTickleState = e_idle;
}

// FUNCTION: LEGO1 0x100b4fc0
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

		char worldValue[512];
		if (KeyValueStringParse(worldValue, g_strWORLD, extraCopy)) {
			char* token = strtok(worldValue, g_parseExtraTokens);
			char buf[256];
			strcpy(buf, token);

			token = strtok(NULL, g_parseExtraTokens);
			MxS32 val = token ? atoi(token) : 0;
			MxEntity* result = MxOmni::GetInstance()->AddToWorld(buf, val, this);

			m_action->SetFlags(m_action->GetFlags() | MxDSAction::c_world);

			if (result) {
				SendToCompositePresenter(MxOmni::GetInstance());
			}
		}
	}
}

// FUNCTION: LEGO1 0x100b5120
void MxPresenter::SendToCompositePresenter(MxOmni* p_omni)
{
	if (m_compositePresenter) {
		MxAutoLocker lock(&m_criticalSection);

#ifdef COMPAT_MODE
		{
			MxNotificationParam param(c_notificationPresenter, this);
			NotificationManager()->Send(m_compositePresenter, &param);
		}
#else
		NotificationManager()->Send(m_compositePresenter, &MxNotificationParam(c_notificationPresenter, this));
#endif

		m_action->SetOrigin(p_omni ? p_omni : MxOmni::GetInstance());
		m_compositePresenter = NULL;
	}
}

// FUNCTION: LEGO1 0x100b5200
MxResult MxPresenter::Tickle()
{
	MxAutoLocker lock(&this->m_criticalSection);

	switch (this->m_currentTickleState) {
	case e_ready:
		this->ReadyTickle();

		if (m_currentTickleState != e_starting) {
			break;
		}
	case e_starting:
		this->StartingTickle();

		if (m_currentTickleState != e_streaming) {
			break;
		}
	case e_streaming:
		this->StreamingTickle();

		if (m_currentTickleState != e_repeating) {
			break;
		}
	case e_repeating:
		this->RepeatingTickle();

		if (m_currentTickleState != e_unk5) {
			break;
		}
	case e_unk5:
		this->Unk5Tickle();

		if (m_currentTickleState != e_done) {
			break;
		}
	case e_done:
		this->DoneTickle();
	default:
		break;
	}

	return SUCCESS;
}

// FUNCTION: LEGO1 0x100b52d0
void MxPresenter::Enable(MxBool p_enable)
{
	if (this->m_action && this->IsEnabled() != p_enable) {
		MxU32 flags = this->m_action->GetFlags();

		if (p_enable) {
			this->m_action->SetFlags(flags | MxDSAction::c_enabled);
		}
		else {
			this->m_action->SetFlags(flags & ~MxDSAction::c_enabled);
		}
	}
}

// FUNCTION: LEGO1 0x100b5310
const char* PresenterNameDispatch(const MxDSAction& p_action)
{
	const char* name = p_action.GetSourceName();
	MxS32 format;

	if (!name || strlen(name) == 0) {
		switch (p_action.GetType()) {
		case MxDSObject::e_anim:
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

		case MxDSObject::e_sound:
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

		case MxDSObject::e_serialAction:
		case MxDSObject::e_parallelAction:
		case MxDSObject::e_selectAction:
			name = "MxCompositePresenter";
			break;

		case MxDSObject::e_event:
			name = "MxEventPresenter";
			break;

		case MxDSObject::e_still:
			name = "MxStillPresenter";
			break;
		}
	}

	return name;
}

// FUNCTION: LEGO1 0x100b5410
MxEntity* MxPresenter::CreateEntity(const char* p_name)
{
	char buffer[512];
	char buffer2[512];
	strcpy(buffer, p_name);

	MxU16 extraLen = m_action->GetExtraLength();

	buffer[0] = extraLen;
	buffer[1] = extraLen >> 8;
	if (extraLen) {
		extraLen &= MAXWORD;
		memcpy(buffer2 + 2, m_action->GetExtraData(), extraLen);
		buffer2[extraLen + 2] = 0;
		KeyValueStringParse(buffer, g_strOBJECT, buffer2 + 2);
	}

	return (MxEntity*) ObjectFactory()->Create(buffer);
}

// FUNCTION: LEGO1 0x100b54c0
MxBool MxPresenter::IsEnabled()
{
	return this->m_action && this->m_action->GetFlags() & MxDSAction::c_enabled;
}
