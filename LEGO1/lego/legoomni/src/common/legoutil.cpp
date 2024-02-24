#include "legoutil.h"

#include "legoinputmanager.h"
#include "legoomni.h"
#include "legoworld.h"
#include "legoworldlist.h"
#include "mxdsaction.h"
#include "mxnotificationmanager.h"
#include "mxomni.h"
#include "mxstreamer.h"
#include "mxtypes.h"

#include <process.h>
#include <string.h>

DECOMP_SIZE_ASSERT(NamedTexture, 0x14)

// STUB: LEGO1 0x1003e050
void FUN_1003e050(LegoAnimPresenter* p_presenter)
{
	// TODO
}

// FUNCTION: LEGO1 0x1003e300
Extra::ActionType MatchActionString(const char* p_str)
{
	Extra::ActionType result = Extra::ActionType::e_unknown;

	if (!strcmpi("openram", p_str)) {
		result = Extra::ActionType::e_openram;
	}
	else if (!strcmpi("opendisk", p_str)) {
		result = Extra::ActionType::e_opendisk;
	}
	else if (!strcmpi("close", p_str)) {
		result = Extra::ActionType::e_close;
	}
	else if (!strcmpi("start", p_str)) {
		result = Extra::ActionType::e_start;
	}
	else if (!strcmpi("stop", p_str)) {
		result = Extra::ActionType::e_stop;
	}
	else if (!strcmpi("run", p_str)) {
		result = Extra::ActionType::e_run;
	}
	else if (!strcmpi("exit", p_str)) {
		result = Extra::ActionType::e_exit;
	}
	else if (!strcmpi("enable", p_str)) {
		result = Extra::ActionType::e_enable;
	}
	else if (!strcmpi("disable", p_str)) {
		result = Extra::ActionType::e_disable;
	}
	else if (!strcmpi("notify", p_str)) {
		result = Extra::ActionType::e_notify;
	}

	return result;
}

MxBool CheckIfEntityExists(MxBool p_enable, const char* p_filename, MxS32 p_entityId);
void NotifyEntity(const char* p_filename, MxS32 p_entityId, LegoEntity* p_sender);

// FUNCTION: LEGO1 0x1003e430
void InvokeAction(Extra::ActionType p_actionId, MxAtomId& p_pAtom, int p_targetEntityId, LegoEntity* p_sender)
{
	MxDSAction action;
	action.SetAtomId(p_pAtom);
	action.SetObjectId(p_targetEntityId);

	switch (p_actionId) {
	case Extra::ActionType::e_opendisk:
		if (!CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_targetEntityId)) {
			Streamer()->Open(p_pAtom.GetInternal(), MxStreamer::e_diskStream);
			Start(&action);
		}
		break;
	case Extra::ActionType::e_openram:
		if (!CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_targetEntityId)) {
			Streamer()->Open(p_pAtom.GetInternal(), MxStreamer::e_RAMStream);
			Start(&action);
		}
		break;
	case Extra::ActionType::e_close:
		action.SetUnknown24(-2);
		DeleteObject(action);
		Streamer()->Close(p_pAtom.GetInternal());
		break;
	case Extra::ActionType::e_start:
		if (!CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_targetEntityId)) {
			Start(&action);
		}
		break;
	case Extra::ActionType::e_stop:
		action.SetUnknown24(-2);
		if (!FUN_1003ee00(p_pAtom, p_targetEntityId)) {
			DeleteObject(action);
		}
		break;
	case Extra::ActionType::e_run:
		_spawnl(0, "\\lego\\sources\\main\\main.exe", "\\lego\\sources\\main\\main.exe", "/script", &p_pAtom, 0);
		break;
	case Extra::ActionType::e_exit:
		Lego()->SetExit(TRUE);
		break;
	case Extra::ActionType::e_enable:
		CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_targetEntityId);
		break;
	case Extra::ActionType::e_disable:
		CheckIfEntityExists(FALSE, p_pAtom.GetInternal(), p_targetEntityId);
		break;
	case Extra::ActionType::e_notify:
		NotifyEntity(p_pAtom.GetInternal(), p_targetEntityId, p_sender);
		break;
	}
}

// FUNCTION: LEGO1 0x1003e670
MxBool CheckIfEntityExists(MxBool p_enable, const char* p_filename, MxS32 p_entityId)
{
	LegoWorld* world = FindWorld(MxAtomId(p_filename, e_lowerCase2), p_entityId);

	if (world) {
		world->Enable(p_enable);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

// FUNCTION: LEGO1 0x1003e700
void NotifyEntity(const char* p_filename, MxS32 p_entityId, LegoEntity* p_sender)
{
	MxAtomId atom(p_filename, e_lowerCase2);
	LegoEntity* entity = FindWorld(atom, p_entityId);

	if (entity == NULL) {
		LegoWorldListCursor cursor(Lego()->GetWorldList());
		LegoWorld* world;

		while (cursor.Next(world)) {
			entity = (LegoEntity*) world->Find(atom, p_entityId);

			if (entity != NULL) {
				break;
			}
		}
	}

	if (entity != NULL) {
#ifdef COMPAT_MODE
		{
			MxNotificationParam param(c_notificationType0, p_sender);
			NotificationManager()->Send(entity, &param);
		}
#else
		NotificationManager()->Send(entity, &MxNotificationParam(c_notificationType0, p_sender));
#endif
	}
}

// FUNCTION: LEGO1 0x1003eab0
void SetCameraControllerFromIsle()
{
	InputManager()->SetCamera(FindWorld(*g_isleScript, 0)->GetCamera());
}

// FUNCTION: LEGO1 0x1003eae0
void ConvertHSVToRGB(float p_h, float p_s, float p_v, float* p_rOut, float* p_bOut, float* p_gOut)
{
	double calc;
	double p;
	MxLong hueIndex;
	double v9;
	double v12;
	double v13;

	double sDbl = p_s;

	if (p_s > 0.5f) {
		calc = (1.0f - p_v) * p_s + p_v;
	}
	else {
		calc = (p_v + 1.0) * sDbl;
	}
	if (calc <= 0.0) {
		*p_gOut = 0.0f;
		*p_bOut = 0.0f;
		*p_rOut = 0.0f;
		return;
	}
	p = p_s * 2.0f - calc;
	hueIndex = p_h * 6.0;
	v9 = (p_h * 6.0 - (float) hueIndex) * ((calc - p) / calc) * calc;
	v12 = p + v9;
	v13 = calc - v9;
	switch (hueIndex) {
	case 0:
		*p_rOut = calc;
		*p_bOut = v12;
		*p_gOut = p;
		break;
	case 1:
		*p_rOut = v13;
		*p_bOut = calc;
		*p_gOut = p;
		break;
	case 2:
		*p_rOut = p;
		*p_bOut = calc;
		*p_gOut = v12;
		break;
	case 3:
		*p_rOut = p;
		*p_bOut = v13;
		*p_gOut = calc;
		break;
	case 4:
		*p_rOut = v12;
		*p_bOut = p;
		*p_gOut = calc;
		break;
	case 5:
		*p_rOut = calc;
		*p_bOut = p;
		*p_gOut = v13;
		break;
	case 6:
		*p_rOut = calc;
		*p_bOut = p;
		*p_gOut = v13;
		break;
	default:
		return;
	}
}

// STUB: LEGO1 0x1003ee00
MxBool FUN_1003ee00(MxAtomId& p_atomId, MxS32 p_id)
{
	return TRUE;
}

// FUNCTION: LEGO1 0x1003ee80
MxBool RemoveFromWorld(MxAtomId& p_entityAtom, MxS32 p_entityId, MxAtomId& p_worldAtom, MxS32 p_worldEntityId)
{
	LegoWorld* world = FindWorld(p_worldAtom, p_worldEntityId);

	if (world) {
		MxCore* object = world->Find(p_entityAtom, p_entityId);

		if (object) {
			world->Remove(object);

			if (!object->IsA("MxPresenter")) {
				delete object;
			}
			else {
				if (((MxPresenter*) object)->GetAction()) {
					FUN_100b7220(((MxPresenter*) object)->GetAction(), MxDSAction::c_world, FALSE);
				}

				((MxPresenter*) object)->EndAction();
			}

			return TRUE;
		}
	}

	return FALSE;
}

// STUB: LEGO1 0x1003ef00
void FUN_1003ef00(MxBool)
{
	// TODO (something related to animation manager)
}

// FUNCTION: LEGO1 0x1003ef40
void SetAppCursor(WPARAM p_wparam)
{
	PostMessageA(MxOmni::GetInstance()->GetWindowHandle(), 0x5400, p_wparam, 0);
}

// STUB: LEGO1 0x1003ef60
MxBool FUN_1003ef60()
{
	return TRUE;
}

// STUB: LEGO1 0x1003f3b0
NamedTexture* ReadNamedTexture(LegoFile* p_file)
{
	return NULL;
}

// STUB: LEGO1 0x1003f540
void FUN_1003f540(LegoFile* p_file, const char* p_filename)
{
}

// FUNCTION: LEGO1 0x1003f8a0
void WriteNamedTexture(LegoFile* p_file, NamedTexture* p_texture)
{
	p_file->FUN_10006030(*p_texture->GetName());
	p_texture->GetTexture()->Write(p_file);
}
