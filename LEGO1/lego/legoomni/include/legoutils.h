#ifndef LEGOUTILS_H
#define LEGOUTILS_H

#include "decomp.h"
#include "extra.h"
#include "mxtypes.h"

#include <windows.h>

class IslePathActor;
class MxAtomId;
class LegoEntity;
class LegoFile;
class LegoAnimPresenter;
class LegoNamedTexture;
class LegoROI;
class LegoTreeNode;

LegoEntity* PickEntity(MxLong, MxLong);
LegoROI* PickROI(MxLong, MxLong);
MxS16 CountTotalTreeNodes(LegoTreeNode* p_node);
void FUN_1003e050(LegoAnimPresenter* p_presenter);
Extra::ActionType MatchActionString(const char*);
void InvokeAction(Extra::ActionType p_actionId, const MxAtomId& p_pAtom, MxS32 p_targetEntityId, LegoEntity* p_sender);
void SetCameraControllerFromIsle();
void ConvertHSVToRGB(float p_h, float p_s, float p_v, float* p_rOut, float* p_bOut, float* p_gOut);
void PlayCamAnim(IslePathActor* p_actor, undefined4 p_unused, MxU32 p_location, MxBool p_bool);
void FUN_1003eda0();
MxBool RemoveFromCurrentWorld(const MxAtomId& p_atomId, MxS32 p_id);
void FUN_1003ef00(MxBool p_enable);
void SetAppCursor(WPARAM p_wparam);
MxBool FUN_1003ef60();
MxBool RemoveFromWorld(MxAtomId& p_entityAtom, MxS32 p_entityId, MxAtomId& p_worldAtom, MxS32 p_worldEntityId);
MxS32 UpdateLightPosition(MxS32 p_increase);
void SetLightPosition(MxS32 p_index);
LegoNamedTexture* ReadNamedTexture(LegoFile* p_file);
void FUN_1003f540(LegoFile* p_file, const char* p_filename);
void WriteNamedTexture(LegoFile* p_file, LegoNamedTexture* p_texture);

// SYNTHETIC: LEGO1 0x10034b40
// LegoTexture::`scalar deleting destructor'

#endif // LEGOUTILS_H
