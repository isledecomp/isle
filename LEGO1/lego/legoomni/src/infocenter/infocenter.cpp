#include "infocenter.h"

#include "infocenterstate.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"
#include "mxactionnotificationparam.h"
#include "mxbackgroundaudiomanager.h"
#include "mxnotificationmanager.h"
#include "mxstillpresenter.h"

DECOMP_SIZE_ASSERT(Infocenter, 0x1d8)

// FUNCTION: LEGO1 0x1006ea20
Infocenter::Infocenter()
{
	m_unk0xfc = 0;
	m_unk0x11c = 0;
	m_infocenterState = NULL;
	m_unk0x11c = 0;
	m_unk0x104 = 0;
	m_unk0xf8 = -1;
	m_currentCutScene = -1;
	memset(&m_entries, 0, sizeof(InfocenterUnkDataEntry) * 7);
	m_unk0x1c8 = -1;
	SetAppCursor(1);
	NotificationManager()->Register(this);
	m_unk0x1d0 = 0;
	m_unk0x1d2 = 0;
	m_unk0x1d4 = 0;
	m_unk0x1d6 = 0;
}

// STUB: LEGO1 0x1006ec90
Infocenter::~Infocenter()
{
	// TODO
}

// STUB: LEGO1 0x1006ed90
MxResult Infocenter::Create(MxDSAction& p_dsAction)
{
	OutputDebugString("create called\n");
	if (LegoWorld::Create(p_dsAction) == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
	}

	LegoGameState* gs = GameState();
	m_infocenterState = (InfocenterState*) gs->GetState("InfocenterState");
	if (!m_infocenterState) {
		m_infocenterState = (InfocenterState*) gs->CreateState("InfocenterState");
		m_infocenterState->SetUnknown0x74(3);
	}
	else {
		// TODO
	}

	// TODO
	InputManager()->Register(this);
	SetIsWorldActive(FALSE);
	return SUCCESS;
}

// FUNCTION: LEGO1 0x1006ef10
MxLong Infocenter::Notify(MxParam& p_param)
{
	LegoWorld::Notify(p_param);

	if (m_worldStarted) {

		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case 0:
			return HandleNotification0(p_param);
		case c_notificationEndAction:
			return HandleEndAction(p_param);
		case c_notificationKeyPress:
			return HandleKeyPress(((LegoEventNotificationParam&) p_param).GetKey()) & 0xff;
		case c_notificationButtonUp:
			return HandleButtonUp(
					   ((LegoEventNotificationParam&) p_param).GetX(),
					   ((LegoEventNotificationParam&) p_param).GetY()
				   ) &
				   0xff;
		case c_notificationMouseMove:
			return HandleMouseMove(
					   ((LegoEventNotificationParam&) p_param).GetX(),
					   ((LegoEventNotificationParam&) p_param).GetY()
				   ) &
				   0xff;
		case TYPE17:
			return HandleNotification17(p_param);
		case MXTRANSITIONMANAGER_TRANSITIONENDED:
			FUN_10071550();
			m_unk0x1d2 = 0;
			if (m_infocenterState->GetUnknown0x74() == 0xc) {
				StartCredits();
				m_infocenterState->SetUnknown0x74(0xd);
				return 0;
			}
			if (m_unk0x104 != 0) {
				BackgroundAudioManager()->RaiseVolume();
				GameState()->HandleAction(m_unk0x104);
				m_unk0x104 = 0;
			}
			break;
		}
	}
	return 0;
}

// FUNCTION: LEGO1 0x1006f4e0
void Infocenter::VTable0x50()
{
	m_unk0x1d0 = 0;
	m_unk0x1d2 = 0;
	m_unk0x1d4 = 0;
	m_unk0x1d6 = 0;

	MxStillPresenter* bg = (MxStillPresenter*) FindPresenter("MxStillPresenter", "Background_Bitmap");
	MxStillPresenter* bgRed = (MxStillPresenter*) FindPresenter("MxStillPresenter", "BackgroundRed_Bitmap");

	switch (GameState()->GetUnknown10()) {
	case 0:
		// bg->Enable(1);
		InitializeBitmaps();
		switch (m_infocenterState->GetUnknown0x74()) {
		case 3:
			PlayCutScene(0, TRUE);
			m_infocenterState->SetUnknown0x74(0);
			return;
		case 4:
			m_infocenterState->SetUnknown0x74(2);
			if (m_infocenterState->GetInfocenterBufferElement(0) == 0) {
				m_unk0x1d2 = 1;
			}

			FUN_10071300(504); // Play "Ok, lets get started" dialogue
			PlayMusic(11);
			FUN_10015820(0, 7);
			return;
		default:
			PlayMusic(11);
			// TODO
			break;
		case 8:
			PlayMusic(11);
			FUN_10071300(522); // Are you sure you want to exit lego island?
			FUN_10015820(0, 7);
			return;
		case 0xf:
			if (m_infocenterState->GetInfocenterBufferElement(0) == 0) {
				m_unk0x1d2 = 1;
			}
			FUN_10071300(502);
			PlayMusic(11);
			FUN_10015820(0, 7);
			return;
		}
		break;
	case 1:
		// TODO
		break;
	case 2:
		// TODO
		break;
	default:
		m_infocenterState->SetUnknown0x74(11);
		FUN_10015820(0, 7);
		return;
	}
}

// STUB: LEGO1 0x10070aa0
void Infocenter::VTable0x68(MxBool p_add)
{
	// TODO
}

// STUB: LEGO1 0x1006f9a0
void Infocenter::InitializeBitmaps()
{
	// TODO: Infocenter class size is wrong
}

// STUB: LEGO1 0x1006fd00
MxLong Infocenter::HandleMouseMove(MxS32 p_x, MxS32 p_y)
{
	return 1;
}

// STUB: LEGO1 0x1006fda0
MxU8 Infocenter::HandleKeyPress(char p_key)
{
	return 1;
}

// STUB: LEGO1 0x1006feb0
MxU8 Infocenter::HandleButtonUp(MxS32 p_x, MxS32 p_y)
{
	return 1;
}

// STUB: LEGO1 0x10070370
MxU8 Infocenter::HandleNotification17(MxParam&)
{
	return 1;
}

// STUB: LEGO1 0x1006f080
MxLong Infocenter::HandleEndAction(MxParam& p_param)
{
	MxDSAction* endedAction = ((MxEndActionNotificationParam&) p_param).GetAction();
	if (endedAction->GetAtomId() == *g_creditsScript && endedAction->GetObjectId() == 499) {
		Lego()->CloseMainWindow();
	}

	// TODO
	return 1;
}

// STUB: LEGO1 0x10070870
MxLong Infocenter::HandleNotification0(MxParam&)
{
	return 1;
}

// STUB: LEGO1 0x10070af0
MxResult Infocenter::Tickle()
{
	// TODO
	return LegoWorld::Tickle();
}

// FUNCTION: LEGO1 0x10070c20
void Infocenter::PlayCutScene(MxU32 p_entityId, MxBool p_scale)
{
	m_currentCutScene = p_entityId;
	VideoManager()->EnableFullScreenMovie(TRUE, p_scale);
	InputManager()->SetUnknown336(TRUE);
	InputManager()->SetUnknown335(TRUE);
	SetAppCursor(0xb);                                   // Hide cursor
	VideoManager()->GetDisplaySurface()->FUN_100ba640(); // Clear screen

	if (m_currentCutScene != -1) {
		// check if the cutscene is not an ending
		if (m_currentCutScene >= 4 && m_currentCutScene <= 5) {
			FUN_10070e90();
		}
		InvokeAction(ExtraActionType_opendisk, *g_introScript, m_currentCutScene, NULL);
	}
}

// FUNCTION: LEGO1 0x10070d00
MxBool Infocenter::VTable0x5c()
{
	return TRUE;
}

// STUB: LEGO1 0x10070e90
void Infocenter::FUN_10070e90()
{
}

// STUB: LEGO1 0x10070f60
MxBool Infocenter::VTable0x64()
{
	return FALSE;
}

// STUB: LEGO1 0x10071030
void Infocenter::StartCredits()
{
}

// FUNCTION: LEGO1 0x10071250
void DeleteCredits()
{
	MxDSAction action;
	action.SetObjectId(499);
	action.SetAtomId(*g_creditsScript);
	action.SetUnknown24(-2);
	DeleteObject(action);
}

// FUNCTION: LEGO1 0x10071300
void Infocenter::FUN_10071300(MxS32 p_objectId)
{
	MxDSAction action;
	action.SetObjectId(p_objectId);
	action.SetAtomId(*g_infomainScript);
	FUN_100713d0();

	m_unk0xf8 = p_objectId;
	BackgroundAudioManager()->LowerVolume();
	Start(&action);
}

// FUNCTION: LEGO1 0x100713d0
void Infocenter::FUN_100713d0()
{
	if (m_unk0xf8 != -1) {
		MxDSAction action;
		action.SetObjectId(m_unk0xf8);
		action.SetAtomId(*g_infomainScript);
		action.SetUnknown24(-2);
		DeleteObject(action);
		m_unk0xf8 = -1;
	}
}

// FUNCTION: LEGO1 0x100714a0
void Infocenter::FUN_100714a0()
{
	MxDSAction action;
	action.SetObjectId(400);
	action.SetAtomId(*g_sndAnimScript);
	Start(&action);
}

// FUNCTION: LEGO1 0x10071550
void Infocenter::FUN_10071550()
{
	MxDSAction action;
	action.SetObjectId(400);
	action.SetAtomId(*g_sndAnimScript);
	action.SetUnknown24(-2);
	DeleteObject(action);
}
