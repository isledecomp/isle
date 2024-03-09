#ifndef LEGOUTIL_H
#define LEGOUTIL_H

#include "extra.h"
#include "misc/legostorage.h"
#include "misc/legotexture.h"
#include "mxstring.h"
#include "mxtypes.h"
#include "mxutil.h"

#include <windows.h>

class MxAtomId;
class LegoEntity;
class LegoAnimPresenter;
class LegoNamedTexture;

void FUN_1003e050(LegoAnimPresenter* p_presenter);
Extra::ActionType MatchActionString(const char*);
void InvokeAction(Extra::ActionType p_actionId, MxAtomId& p_pAtom, int p_targetEntityId, LegoEntity* p_sender);
void SetCameraControllerFromIsle();
void ConvertHSVToRGB(float p_h, float p_s, float p_v, float* p_rOut, float* p_bOut, float* p_gOut);
MxBool FUN_1003ee00(MxAtomId& p_atomId, MxS32 p_id);
void FUN_1003ef00(MxBool);
void SetAppCursor(WPARAM p_wparam);
MxBool FUN_1003ef60();
MxBool RemoveFromWorld(MxAtomId& p_atomId1, MxS32 p_id1, MxAtomId& p_atomId2, MxS32 p_id2);
void SetLightPosition(MxU32);
LegoNamedTexture* ReadNamedTexture(LegoFile* p_file);
void FUN_1003f540(LegoFile* p_file, const char* p_filename);
void WriteNamedTexture(LegoFile* p_file, LegoNamedTexture* p_texture);

// SYNTHETIC: LEGO1 0x10034b40
// LegoTexture::`scalar deleting destructor'

#endif // LEGOUTIL_H
