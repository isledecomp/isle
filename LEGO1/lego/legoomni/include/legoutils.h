#ifndef LEGOUTILS_H
#define LEGOUTILS_H

#include "actionsfwd.h"
#include "decomp.h"
#include "extra.h"
#include "mxtypes.h"

#include <windows.h>

#define WM_ISLE_SETCURSOR 0x5400

// name verified by BETA10 0x100d4054
#define DS_NOT_A_STREAM -1

enum Cursor {
	e_cursorArrow = 0,
	e_cursorBusy,
	e_cursorNo,
	e_cursorUnused3,
	e_cursorUnused4,
	e_cursorUnused5,
	e_cursorUnused6,
	e_cursorUnused7,
	e_cursorUnused8,
	e_cursorUnused9,
	e_cursorUnused10,
	e_cursorNone
};

class BoundingSphere;
class MxAtomId;
class LegoEntity;
class LegoAnimPresenter;
class LegoNamedTexture;
class LegoPathActor;
class LegoROI;
class LegoStorage;
class LegoTreeNode;

extern MxAtomId* g_isleScript;

LegoEntity* PickEntity(MxLong p_x, MxLong p_y);
LegoROI* PickROI(MxLong p_x, MxLong p_y);
LegoROI* PickRootROI(MxLong p_x, MxLong p_y);
void RotateY(LegoROI* p_roi, MxFloat p_angle);
MxBool SpheresIntersect(const BoundingSphere& p_sphere1, const BoundingSphere& p_sphere2);
MxBool CalculateRayOriginDirection(MxFloat p_coordinates[2], MxFloat p_direction[3], MxFloat p_origin[3]);
MxBool TransformWorldToScreen(const MxFloat p_world[3], MxFloat p_screen[4]);
MxS16 CountTotalTreeNodes(LegoTreeNode* p_node);
LegoTreeNode* GetTreeNode(LegoTreeNode* p_node, MxU32 p_index);
void CalculateViewFromAnimation(LegoAnimPresenter* p_presenter);
Extra::ActionType MatchActionString(const char*);
void InvokeAction(Extra::ActionType p_actionId, const MxAtomId& p_pAtom, MxS32 p_streamId, LegoEntity* p_sender);
void SetCameraControllerFromIsle();
void ConvertHSVToRGB(float p_h, float p_s, float p_v, float* p_rOut, float* p_bOut, float* p_gOut);
void PlayCamAnim(LegoPathActor* p_actor, MxBool p_unused, MxU32 p_location, MxBool p_bool);
void ResetViewVelocity();
MxBool RemoveFromCurrentWorld(const MxAtomId& p_atomId, MxS32 p_id);
void EnableAnimations(MxBool p_enable);
void SetAppCursor(Cursor p_cursor);
MxBool CanExit();
MxBool RemoveFromWorld(MxAtomId& p_entityAtom, MxS32 p_entityId, MxAtomId& p_worldAtom, MxS32 p_worldEntityId);
MxS32 UpdateLightPosition(MxS32 p_increase);
void SetLightPosition(MxS32 p_index);
LegoNamedTexture* ReadNamedTexture(LegoStorage* p_storage);
void WriteDefaultTexture(LegoStorage* p_storage, const char* p_name);
void WriteNamedTexture(LegoStorage* p_storage, LegoNamedTexture* p_namedTexture);
void LoadFromNamedTexture(LegoNamedTexture* p_namedTexture);

// FUNCTION: BETA10 0x100260a0
inline void StartIsleAction(IsleScript::Script p_objectId)
{
	if (p_objectId != (IsleScript::Script) -1) {
		InvokeAction(Extra::e_start, *g_isleScript, p_objectId, NULL);
	}
}

// SYNTHETIC: LEGO1 0x10034b40
// LegoTexture::`scalar deleting destructor'

#endif // LEGOUTILS_H
