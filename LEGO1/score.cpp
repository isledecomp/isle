#include "score.h"

#include "ambulancemissionstate.h"
#include "gifmanager.h"
#include "legocontrolmanager.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legoomni.h"
#include "mxnotificationmanager.h"
#include "mxnotificationparam.h"
#include "mxtransitionmanager.h"
#include "pizzamissionstate.h"
#include "racestate.h"
#include "towtrackmissionstate.h"

DECOMP_SIZE_ASSERT(Score, 0x104)

// FUNCTION: LEGO1 0x10001000
Score::Score()
{
	m_unk0xf8 = 0;
	NotificationManager()->Register(this);
}

// FUNCTION: LEGO1 0x100010b0
MxBool Score::VTable0x5c()
{
	return TRUE;
}

// FUNCTION: LEGO1 0x10001200
Score::~Score()
{
	if (InputManager()->GetWorld() == this)
		InputManager()->ClearWorld();
	InputManager()->UnRegister(this);
	ControlManager()->Unregister(this);
	NotificationManager()->Unregister(this);
}

// FUNCTION: LEGO1 0x100012a0
MxResult Score::Create(MxDSObject& p_dsObject)
{
	MxResult result = SetAsCurrentWorld(p_dsObject);

	if (result == SUCCESS) {
		InputManager()->SetWorld(this);
		ControlManager()->Register(this);
		InputManager()->Register(this);
		SetIsWorldActive(FALSE);
		LegoGameState* gs = GameState();
		ScoreState* state = (ScoreState*) gs->GetState("ScoreState");
		m_state = state ? state : (ScoreState*) gs->CreateState("ScoreState");
		GameState()->SetUnknown424(0xd);
		GameState()->FUN_1003a720(0);
	}

	return result;
}

// FUNCTION: LEGO1 0x10001340
void Score::DeleteScript()
{
	if (m_state->GetTutorialFlag()) {
		MxDSAction action;
		action.SetObjectId(0x1f5);
		action.SetAtomId(*g_infoscorScript);
		action.SetUnknown24(-2);
		DeleteObject(action);
		m_state->SetTutorialFlag(FALSE);
	}
}

// FUNCTION: LEGO1 0x10001410
MxLong Score::Notify(MxParam& p_param)
{
	MxLong ret = 0;
	LegoWorld::Notify(p_param);
	if (m_unk0xf6) {
		switch (((MxNotificationParam&) p_param).GetNotification()) {
		case c_notificationStartAction:
			ret = 1;
			Paint();
			break;
		case c_notificationEndAction:
			ret = FUN_10001510((MxEndActionNotificationParam&) p_param);
			break;
		case c_notificationKeyPress:
			if (((LegoEventNotificationParam&) p_param).GetKey() == 0x20)
				DeleteScript(); // Shutting down
			ret = 1;
			break;
		case TYPE17:
			ret = FUN_100016d0((MxType17NotificationParam&) p_param);
			break;
		case MXTRANSITIONMANAGER_TRANSITIONENDED:
			DeleteObjects(g_infoscorScript, 7, 9);
			if (m_unk0xf8)
				GameState()->HandleAction(m_unk0xf8);
			ret = 1;
			break;
		default:
			break;
		}
	}
	return ret;
}

// FUNCTION: LEGO1 0x10001510
MxLong Score::FUN_10001510(MxEndActionNotificationParam& p_param)
{
	MxDSAction* action = p_param.GetAction();

	if (m_atom == action->GetAtomId()) {
		MxU32 id = action->GetObjectId();
		switch (action->GetObjectId()) {
		case 10:
			m_unk0xf8 = 0x38;
			TransitionManager()->StartTransition(MxTransitionManager::PIXELATION, 0x32, 0, 0);
			break;
		case 0x1f5:
			PlayMusic(11);
			m_state->SetTutorialFlag(FALSE);
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10001580
void Score::Stop()
{
	LegoWorld::Stop();

	MxDSAction action;
	action.SetObjectId(0x1f4);
	action.SetAtomId(m_atom);
	action.SetUnknown84(this);
	Start(&action);

	if (m_state->GetTutorialFlag()) {
		MxDSAction action2;
		action.SetObjectId(0x1f5);
		action.SetAtomId(*g_infoscorScript);
		Start(&action);
	}
	else
		PlayMusic(11);

	FUN_10015820(0, 7);
}

// FUNCTION: LEGO1 0x100016d0
MxLong Score::FUN_100016d0(MxType17NotificationParam& p_param)
{
	MxS16 l = p_param.GetUnknown28();

	if (l == 1 || p_param.GetUnknown20() == 4) {
		switch (p_param.GetUnknown20()) {
		case 1:
			m_unk0xf8 = 2;
			DeleteScript();
			TransitionManager()->StartTransition(MxTransitionManager::PIXELATION, 0x32, 0, 0);
			break;
		case 2:
			m_unk0xf8 = 3;
			DeleteScript();
			TransitionManager()->StartTransition(MxTransitionManager::PIXELATION, 0x32, 0, 0);
			break;
		case 3: {
			LegoInputManager* im = InputManager();
			im->SetUnknown88(TRUE);
			im->SetUnknown336(FALSE);
			DeleteScript();

			MxDSAction action;
			action.SetObjectId(10);
			action.SetAtomId(*g_infoscorScript);
			Start(&action);
			break;
		}
		case 4: {
			switch (l) {
			case 1: {
				MxDSAction action;
				action.SetObjectId(7);
				action.SetAtomId(*g_infoscorScript);
				Start(&action);
				break;
			}
			case 2: {
				MxDSAction action;
				action.SetObjectId(8);
				action.SetAtomId(*g_infoscorScript);
				Start(&action);
				break;
			}
			case 3: {
				MxDSAction action;
				action.SetObjectId(9);
				action.SetAtomId(*g_infoscorScript);
				Start(&action);
				break;
			}
			}
			break;
		}
		}
	}

	return 1;
}

// FUNCTION: LEGO1 0x10001980
void Score::VTable0x68(MxBool p_add)
{
	LegoWorld::VTable0x68(p_add);

	if (p_add) {
		InputManager()->SetWorld(this);
		SetIsWorldActive(FALSE);
	}
	else if (InputManager()->GetWorld() == this)
		InputManager()->ClearWorld();
}

// FUNCTION: LEGO1 0x100019d0
void Score::Paint()
{
	GifManager* gm = GetGifManager();
	GifData* gd = gm->Get("bigcube.gif");

	if (gd) {
		RaceState* l78 = (RaceState*) GameState()->GetState("JetskiRaceState");
		RaceState* l70 = (RaceState*) GameState()->GetState("CarRaceState");
		TowTrackMissionState* lesi = (TowTrackMissionState*) GameState()->GetState("TowTrackMissionState");
		PizzaMissionState* l74 = (PizzaMissionState*) GameState()->GetState("PizzaMissionState");
		AmbulanceMissionState* lebp = (AmbulanceMissionState*) GameState()->GetState("AmbulanceMissionState");

		DDSURFACEDESC desc;
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);
		if (gd->m_surface->Lock(NULL, &desc, 0, NULL) == DD_OK) {
			if (desc.lPitch != desc.dwWidth) {
				gd->m_surface->Unlock(desc.lpSurface);
				return;
			}

			for (MxU8 id = 1; id <= 5; id++) {
				m_surface = (MxU8*) desc.lpSurface;
				MxU16 color = 0;
				if (l70)
					color = l70->GetColor(id);
				MxU32 row = id - 1;
				FillArea(0, row, color);
				color = 0;
				if (l78)
					color = l78->GetColor(id);
				FillArea(1, row, color);
				color = 0;
				if (l74)
					color = l74->GetColor(id);
				FillArea(2, row, color);
				color = 0;
				if (lesi)
					color = lesi->GetColor(id);
				FillArea(3, row, color);
				color = 0;
				if (lebp)
					color = lebp->GetColor(id);
				FillArea(4, row, color);
			}

			gd->m_surface->Unlock(desc.lpSurface);
			gd->m_texture->Changed(TRUE, FALSE);
			m_surface = NULL;
		}
	}
}

// FUNCTION: LEGO1 0x10001d20
void Score::FillArea(MxU32 p_x, MxU32 p_y, MxS16 p_color)
{
	MxU32 data[24];
	data[9] = 0x2b00;
	data[10] = 0x5700;
	data[11] = 0x8000;
	data[19] = 0x2a;
	data[12] = 0xab00;
	data[13] = 0xd600;
	data[20] = 0x27;
	data[21] = 0x29;
	data[22] = 0x29;
	data[23] = 0x2a;
	data[4] = 0x2f;
	data[5] = 0x56;
	data[6] = 0x81;
	data[15] = 0x29;
	data[16] = 0x27;
	data[7] = 0xaa;
	data[8] = 0xd4;
	data[14] = 0x25;
	data[0] = 0x11;
	data[17] = 0x28;
	data[18] = 0x28;
	data[1] = 0xf;
	MxU32 size = data[p_x + 14];
	MxU8* ptr = data[p_x + 4] + data[p_y + 9] + m_surface;
	MxS32 count = data[p_y + 19];
	data[2] = 0x8;
	data[3] = 0x5;
	MxU32 value = data[p_color];
	for (; count > 0; count--) {
		memset(ptr++, value, size);
		ptr += 0x100;
	}
}

// FUNCTION: LEGO1 0x10001e40
MxBool Score::VTable0x64()
{
	DeleteScript();
	m_unk0xf8 = 2;
	return TRUE;
}
