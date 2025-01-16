#include "legoutils.h"

#include "3dmanager/lego3dmanager.h"
#include "anim/legoanim.h"
#include "isle.h"
#include "isle_actions.h"
#include "islepathactor.h"
#include "legoanimationmanager.h"
#include "legoanimpresenter.h"
#include "legogamestate.h"
#include "legoinputmanager.h"
#include "legomain.h"
#include "legonamedtexture.h"
#include "legopathstruct.h"
#include "legosoundmanager.h"
#include "legovideomanager.h"
#include "legoworld.h"
#include "legoworldlist.h"
#include "misc.h"
#include "misc/legocontainer.h"
#include "misc/legoimage.h"
#include "misc/legotree.h"
#include "mxdsaction.h"
#include "mxmisc.h"
#include "mxnotificationmanager.h"
#include "mxstreamer.h"
#include "mxtypes.h"
#include "mxutilities.h"
#include "mxvariabletable.h"
#include "realtime/realtime.h"
#include "scripts.h"

#include <process.h>
#include <string.h>
#include <vec.h>

// FUNCTION: LEGO1 0x1003dd70
// FUNCTION: BETA10 0x100d3410
LegoROI* PickROI(MxLong p_x, MxLong p_y)
{
	LegoVideoManager* videoManager = VideoManager();
	Lego3DView* view = videoManager->Get3DManager()->GetLego3DView();
	return (LegoROI*) view->Pick(p_x, p_y);
}

// FUNCTION: LEGO1 0x1003dd90
// FUNCTION: BETA10 0x100d3449
LegoROI* PickRootROI(MxLong p_x, MxLong p_y)
{
	LegoVideoManager* videoManager = VideoManager();
	Lego3DView* view = videoManager->Get3DManager()->GetLego3DView();
	LegoROI* roi = (LegoROI*) view->Pick(p_x, p_y);

	while (roi != NULL && roi->GetParentROI() != NULL) {
		roi = (LegoROI*) roi->GetParentROI();
	}

	return roi;
}

// FUNCTION: LEGO1 0x1003ddc0
LegoEntity* PickEntity(MxLong p_x, MxLong p_y)
{
	LegoROI* roi = PickRootROI(p_x, p_y);

	if (roi == NULL) {
		return NULL;
	}

	return roi->GetEntity();
}

// FUNCTION: LEGO1 0x1003dde0
// FUNCTION: BETA10 0x100d358e
void RotateY(LegoROI* p_roi, MxFloat p_angle)
{
	MxMatrix mat;
	const Matrix4& local2world = p_roi->GetLocal2World();
	mat = local2world;

	float fsin = sin(p_angle);
	float fcos = cos(p_angle);

	for (MxS32 i = 0; i < 3; i++) {
		mat[i][0] = (local2world[i][0] * fcos) + (local2world[i][2] * fsin);
		mat[i][2] = (local2world[i][2] * fcos) - (local2world[i][0] * fsin);
	}

	p_roi->WrappedSetLocalTransform(mat);
}

// FUNCTION: LEGO1 0x1003de80
MxBool SpheresIntersect(const BoundingSphere& p_sphere1, const BoundingSphere& p_sphere2)
{
	// This doesn't look clean, but it matches.
	// p_sphere1.Center().GetData() doesn't work out
	return sqrt(DISTSQRD3(&p_sphere1.Center()[0], &p_sphere2.Center()[0])) < p_sphere1.Radius() + p_sphere2.Radius();
}

// FUNCTION: LEGO1 0x1003ded0
// FUNCTION: BETA10 0x100d3802
MxBool FUN_1003ded0(MxFloat p_param1[2], MxFloat p_param2[3], MxFloat p_param3[3])
{
	MxFloat local1c[4];
	MxFloat local10[3];

	Tgl::View* view = VideoManager()->Get3DManager()->GetLego3DView()->GetView();

	local1c[0] = p_param1[0];
	local1c[1] = p_param1[1];
	local1c[2] = 1.0f;
	local1c[3] = 1.0f;

	view->TransformScreenToWorld(local1c, p_param3);

	local1c[0] *= 2.0;
	local1c[1] *= 2.0;
	local1c[3] = 2.0;

	view->TransformScreenToWorld(local1c, local10);

	p_param2[0] = local10[0] - p_param3[0];
	p_param2[1] = local10[1] - p_param3[1];
	p_param2[2] = local10[2] - p_param3[2];
	return TRUE;
}

// FUNCTION: LEGO1 0x1003df70
// FUNCTION: BETA10 0x100d38cb
MxBool TransformWorldToScreen(const MxFloat p_world[3], MxFloat p_screen[4])
{
	VideoManager()->Get3DManager()->GetLego3DView()->GetView()->TransformWorldToScreen(p_world, p_screen);
	return TRUE;
}

// FUNCTION: LEGO1 0x1003df90
// FUNCTION: BETA10 0x100d39a3
MxS16 CountTotalTreeNodes(LegoTreeNode* p_node)
{
	MxS16 result = 1;

	for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
		result += CountTotalTreeNodes(p_node->GetChild(i));
	}

	return result;
}

// FUNCTION: LEGO1 0x1003dfd0
// FUNCTION: BETA10 0x100d3a09
LegoTreeNode* GetTreeNode(LegoTreeNode* p_node, MxU32 p_index)
{
	LegoTreeNode* result = NULL;

	if (p_index == 0) {
		result = p_node;
	}
	else {
		for (LegoU32 i = 0; i < p_node->GetNumChildren(); i++) {
			MxS16 count = CountTotalTreeNodes(p_node->GetChild(i));
			if (p_index > count) {
				p_index -= count;
			}
			else {
				result = GetTreeNode(p_node->GetChild(i), p_index - 1);
				break;
			}
		}
	}

	return result;
}

// FUNCTION: LEGO1 0x1003e050
// FUNCTION: BETA10 0x100d3abc
void FUN_1003e050(LegoAnimPresenter* p_presenter)
{
	MxMatrix viewMatrix;
	LegoTreeNode* rootNode = p_presenter->GetAnimation()->GetRoot();
	LegoAnimNodeData* camData = NULL;
	LegoAnimNodeData* targetData = NULL;
	MxS16 nodesCount = CountTotalTreeNodes(rootNode);

	MxFloat cam;
	for (MxS16 i = 0; i < nodesCount; i++) {
		if (camData && targetData) {
			break;
		}

		LegoAnimNodeData* data = (LegoAnimNodeData*) GetTreeNode(rootNode, i)->GetData();

		if (!strnicmp(data->GetName(), "CAM", strlen("CAM"))) {
			camData = data;
			cam = atof(&data->GetName()[strlen(data->GetName()) - 2]);
		}
		else if (!strcmpi(data->GetName(), "TARGET")) {
			targetData = data;
		}
	}

	MxMatrix matrixCam;
	MxMatrix matrixTarget;
	matrixCam.SetIdentity();
	matrixTarget.SetIdentity();

	camData->CreateLocalTransform(0.0f, matrixCam);
	targetData->CreateLocalTransform(0.0f, matrixTarget);

	Mx3DPointFloat dir;
	dir[0] = matrixTarget[3][0] - matrixCam[3][0];
	dir[1] = matrixTarget[3][1] - matrixCam[3][1];
	dir[2] = matrixTarget[3][2] - matrixCam[3][2];
	dir.Unitize();

	CalcLocalTransform(matrixCam[3], dir, matrixCam[1], viewMatrix);

	LegoVideoManager* video = VideoManager();
	LegoROI* roi = video->GetViewROI();
	Lego3DView* view = video->Get3DManager()->GetLego3DView();

	roi->WrappedSetLocalTransform(viewMatrix);
	view->Moved(*roi);
	FUN_1003eda0();
	video->Get3DManager()->SetFrustrum(cam, 0.1, 250.0);
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
// FUNCTION: BETA10 0x100d3fda
void InvokeAction(Extra::ActionType p_actionId, const MxAtomId& p_pAtom, MxS32 p_streamId, LegoEntity* p_sender)
{
	MxDSAction action;
	action.SetAtomId(p_pAtom);
	action.SetObjectId(p_streamId);

	switch (p_actionId) {
	case Extra::ActionType::e_opendisk:
		assert(p_streamId != DS_NOT_A_STREAM);

		if (!CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_streamId)) {
			Streamer()->Open(p_pAtom.GetInternal(), MxStreamer::e_diskStream);
			Start(&action);
		}

		break;
	case Extra::ActionType::e_openram:
		assert(p_streamId != DS_NOT_A_STREAM);

		if (!CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_streamId)) {
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
		assert(p_streamId != DS_NOT_A_STREAM);

		if (!CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_streamId)) {
			Start(&action);
		}

		break;
	case Extra::ActionType::e_stop:
		assert(p_streamId != DS_NOT_A_STREAM);
		action.SetUnknown24(-2);

		if (!RemoveFromCurrentWorld(p_pAtom, p_streamId)) {
			DeleteObject(action);
		}

		break;
	case Extra::ActionType::e_run:
		_spawnl(0, "\\lego\\sources\\main\\main.exe", "\\lego\\sources\\main\\main.exe", "/script", &p_pAtom, 0);
		break;
	case Extra::ActionType::e_enable:
		assert(p_streamId != DS_NOT_A_STREAM);
		CheckIfEntityExists(TRUE, p_pAtom.GetInternal(), p_streamId);
		break;
	case Extra::ActionType::e_disable:
		assert(p_streamId != DS_NOT_A_STREAM);
		CheckIfEntityExists(FALSE, p_pAtom.GetInternal(), p_streamId);
		break;
	case Extra::ActionType::e_exit:
		Lego()->SetExit(TRUE);
		break;
	case Extra::ActionType::e_notify:
		assert(p_streamId != DS_NOT_A_STREAM);
		NotifyEntity(p_pAtom.GetInternal(), p_streamId, p_sender);
		break;
	default:
		assert("Invalid Action Control" == NULL);
	}
}

// FUNCTION: LEGO1 0x1003e670
// FUNCTION: BETA10 0x100d43f2
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
// FUNCTION: BETA10 0x100d448a
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
		NotificationManager()->Send(entity, MxNotificationParam(c_notificationType0, p_sender));
	}
}

// FUNCTION: LEGO1 0x1003eab0
void SetCameraControllerFromIsle()
{
	InputManager()->SetCamera(FindWorld(*g_isleScript, IsleScript::c__Isle)->GetCameraController());
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

// FUNCTION: LEGO1 0x1003ecc0
// FUNCTION: BETA10 0x100d4b38
void PlayCamAnim(LegoPathActor* p_actor, MxBool p_unused, MxU32 p_location, MxBool p_bool)
{
	LegoWorld* world = CurrentWorld();
	MxLong result = 0;

	if (world != NULL) {
		LegoPathStructNotificationParam param(c_notificationPathStruct, p_actor, LegoPathStruct::c_camAnim, p_location);
		result = world->Notify(param);
	}

	if (result == 0) {
		AnimationManager()->CameraTriggerFire(p_actor, p_unused, p_location, p_bool);
	}
}

// FUNCTION: LEGO1 0x1003eda0
// FUNCTION: BETA10 0x100d4bf4
void FUN_1003eda0()
{
	Mx3DPointFloat vec;
	vec.Clear();

	LegoROI* viewROI = VideoManager()->GetViewROI();
	if (viewROI) {
		viewROI->FUN_100a5a30(vec);
		SoundManager()->UpdateListener(
			viewROI->GetWorldPosition(),
			viewROI->GetWorldDirection(),
			viewROI->GetWorldUp(),
			viewROI->GetWorldVelocity()
		);
	}
}

// FUNCTION: LEGO1 0x1003ee00
// FUNCTION: BETA10 0x100d4c6f
MxBool RemoveFromCurrentWorld(const MxAtomId& p_atomId, MxS32 p_id)
{
	LegoWorld* world = CurrentWorld();

	if (world) {
		MxCore* object = world->Find(p_atomId, p_id);

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

// FUNCTION: LEGO1 0x1003ef00
// FUNCTION: BETA10 0x100d4e1e
void EnableAnimations(MxBool p_enable)
{
	if (p_enable) {
		AnimationManager()->Resume();
	}

	AnimationManager()->FUN_1005f6d0(p_enable);
	AnimationManager()->FUN_10060540(p_enable);
	AnimationManager()->FUN_100604d0(p_enable);
}

// FUNCTION: LEGO1 0x1003ef40
void SetAppCursor(Cursor p_cursor)
{
	PostMessageA(MxOmni::GetInstance()->GetWindowHandle(), WM_ISLE_SETCURSOR, p_cursor, 0);
}

// FUNCTION: LEGO1 0x1003ef60
MxBool FUN_1003ef60()
{
	Act1State* act1State = (Act1State*) GameState()->GetState("Act1State");

	if (GameState()->m_currentArea != LegoGameState::e_elevride &&
		GameState()->m_currentArea != LegoGameState::e_elevride2 &&
		GameState()->m_currentArea != LegoGameState::e_elevopen &&
		GameState()->m_currentArea != LegoGameState::e_seaview &&
		GameState()->m_currentArea != LegoGameState::e_observe &&
		GameState()->m_currentArea != LegoGameState::e_elevdown &&
		GameState()->m_currentArea != LegoGameState::e_garadoor &&
		GameState()->m_currentArea != LegoGameState::e_polidoor) {
		if (UserActor() == NULL || !UserActor()->IsA("TowTrack")) {
			if (UserActor() == NULL || !UserActor()->IsA("Ambulance")) {
				MxU32 unk0x18 = act1State->GetUnknown18();

				if (unk0x18 != 10 && unk0x18 != 8 && unk0x18 != 3) {
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

// FUNCTION: LEGO1 0x1003f050
MxS32 UpdateLightPosition(MxS32 p_increase)
{
	MxS32 lightPosition = atoi(VariableTable()->GetVariable("lightposition"));

	// Only ever increases by 1 irrespective of p_increase
	if (p_increase > 0) {
		lightPosition += 1;
		if (lightPosition > 5) {
			lightPosition = 5;
		}
	}
	else {
		lightPosition -= 1;
		if (lightPosition < 0) {
			lightPosition = 0;
		}
	}

	SetLightPosition(lightPosition);

	char lightPositionBuffer[32];
	sprintf(lightPositionBuffer, "%d", lightPosition);

	VariableTable()->SetVariable("lightposition", lightPositionBuffer);

	return lightPosition;
}

// FUNCTION: LEGO1 0x1003f0d0
void SetLightPosition(MxS32 p_index)
{
	float lights[6][6] = {
		{1.0, 0.0, 0.0, -150.0, 50.0, -50.0},
		{0.809, -0.588, 0.0, -75.0, 50.0, -50.0},
		{0.0, -1.0, 0.0, 0.0, 150.0, -150.0},
		{-0.309, -0.951, 0.0, 25.0, 50.0, -50.0},
		{-0.809, -0.588, 0.0, 75.0, 50.0, -50.0},
		{-1.0, 0.0, 0.0, 150.0, 50.0, -50.0}
	};

	Mx3DPointFloat up(1.0, 0.0, 0.0);
	Mx3DPointFloat direction;
	Mx3DPointFloat position;

	Tgl::FloatMatrix4 matrix;
	Matrix4 in(matrix);
	MxMatrix transform;

	if (p_index < 0) {
		p_index = 0;
	}
	else if (p_index > 5) {
		p_index = 5;
	}

	direction = lights[p_index];
	position = &lights[p_index][3];

	CalcLocalTransform(position, direction, up, transform);
	SETMAT4(in, transform);

	VideoManager()->Get3DManager()->GetLego3DView()->SetLightTransform(FALSE, matrix);
	VideoManager()->Get3DManager()->GetLego3DView()->SetLightTransform(TRUE, matrix);
}

// FUNCTION: LEGO1 0x1003f3b0
LegoNamedTexture* ReadNamedTexture(LegoStorage* p_storage)
{
	LegoTexture* texture = NULL;
	LegoNamedTexture* namedTexture = NULL;
	MxString string;

	p_storage->ReadMxString(string);

	texture = new LegoTexture();
	if (texture != NULL) {
		if (texture->Read(p_storage, 0) != SUCCESS) {
			delete texture;
			return namedTexture;
		}

		namedTexture = new LegoNamedTexture(string.GetData(), texture);
		if (namedTexture == NULL) {
			delete texture;
		}
	}

	return namedTexture;
}

// FUNCTION: LEGO1 0x1003f540
void WriteDefaultTexture(LegoStorage* p_storage, const char* p_name)
{
	MxString name(p_name);
	LegoTextureInfo* textureInfo = TextureContainer()->Get(p_name);

	if (textureInfo != NULL) {
		DDSURFACEDESC desc;
		LegoPaletteEntry paletteEntries[256];

		LPDIRECTDRAWSURFACE surface = textureInfo->m_surface;
		memset(&desc, 0, sizeof(desc));
		desc.dwSize = sizeof(desc);

		if (surface->Lock(NULL, &desc, DDLOCK_SURFACEMEMORYPTR, NULL) == DD_OK) {
			LegoImage* image = new LegoImage(desc.dwWidth, desc.dwHeight);

			if (image != NULL) {
				if (desc.dwWidth == desc.lPitch) {
					memcpy(desc.lpSurface, image->GetBits(), desc.dwWidth * desc.dwHeight);
				}
				else {
					MxU8* surface = (MxU8*) desc.lpSurface;
					const LegoU8* bits = image->GetBits();

					for (MxS32 i = 0; i < desc.dwHeight; i++) {
						memcpy(surface, bits, desc.dwWidth);
						surface += desc.lPitch;
						bits += desc.dwWidth;
					}
				}

				surface->Unlock(desc.lpSurface);

				PALETTEENTRY entries[256];
				if (textureInfo->m_palette->GetEntries(0, 0, sizeOfArray(entries), entries) == DD_OK) {
					MxS32 i;
					for (i = 0; i < sizeOfArray(entries); i++) {
						if (entries[i].peFlags != 0) {
							break;
						}

						paletteEntries[i].SetRed(entries[i].peRed);
						paletteEntries[i].SetGreen(entries[i].peGreen);
						paletteEntries[i].SetBlue(entries[i].peBlue);
					}

					image->SetCount(i);

					if (i > 0) {
						// Note: this appears to be a bug. size should be i * sizeof(LegoPaletteEntry)
						memcpy(image->GetPalette(), paletteEntries, i);
					}

					LegoTexture texture;
					texture.SetImage(image);

					p_storage->WriteMxString(name);
					texture.Write(p_storage);
				}
				else {
					delete image;
				}
			}
			else {
				surface->Unlock(desc.lpSurface);
			}
		}
	}
}

// FUNCTION: LEGO1 0x1003f8a0
void WriteNamedTexture(LegoStorage* p_storage, LegoNamedTexture* p_namedTexture)
{
	p_storage->WriteMxString(*p_namedTexture->GetName());
	p_namedTexture->GetTexture()->Write(p_storage);
}

// FUNCTION: LEGO1 0x1003f930
void FUN_1003f930(LegoNamedTexture* p_namedTexture)
{
	LegoTextureInfo* textureInfo = TextureContainer()->Get(p_namedTexture->GetName()->GetData());

	if (textureInfo != NULL) {
		textureInfo->FUN_10066010(p_namedTexture->GetTexture()->GetImage()->GetBits());
	}
}
