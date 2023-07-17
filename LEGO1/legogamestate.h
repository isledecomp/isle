#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

#include "mxtypes.h"

#include "decomp.h"

class LegoState;
class MxVariable;
class MxString;

class LegoGameState
{
public:
  __declspec(dllexport) LegoGameState();
  __declspec(dllexport) ~LegoGameState();
  __declspec(dllexport) MxResult Load(MxULong);
  __declspec(dllexport) MxResult Save(MxULong p);
  __declspec(dllexport) void SerializePlayersInfo(MxS16 p);
  __declspec(dllexport) void SerializeScoreHistory(MxS16 p);
  __declspec(dllexport) void SetSavePath(char *p);

  LegoState *GetState(char *p_stateName);
  LegoState *CreateState(char *p_stateName);

  void GetFileSavePath(MxString *p_outPath, MxULong p_slotn);

private:
  void RegisterState(LegoState *p_state);

private:
  char *m_savePath;
  MxS16 m_stateCount;
  undefined2 padding1;
  LegoState **m_stateArray;
  MxU8 m_someModeSwitch;
  undefined padding2[3];
  MxU32 m_someEnumState;
  undefined4 unk1;
  MxVariable *m_backgroundColor;
  MxVariable *m_tempBackgroundColor;
  MxVariable *m_fsMovieVariable;
  MxU16 m_secondThingWritten;
};

#endif // LEGOGAMESTATE_H
