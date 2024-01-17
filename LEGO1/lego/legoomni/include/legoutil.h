#ifndef LEGOUTIL_H
#define LEGOUTIL_H

#include "extra.h"
#include "mxtypes.h"
#include "mxutil.h"

#include <windows.h>

class MxAtomId;
class LegoEntity;

Extra::ActionType MatchActionString(const char*);
void InvokeAction(Extra::ActionType p_actionId, MxAtomId& p_pAtom, int p_targetEntityId, LegoEntity* p_sender);
void ConvertHSVToRGB(float p_h, float p_s, float p_v, float* p_rOut, float* p_bOut, float* p_gOut);
MxBool FUN_1003ee00(MxAtomId& p_atomId, MxS32 p_id);
void FUN_1003ef00(MxBool);
void SetAppCursor(WPARAM p_wparam);
MxBool FUN_1003ef60();

#endif // LEGOUTIL_H
