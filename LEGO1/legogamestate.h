#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

#include "decomp.h"
#include "mxtypes.h"
#include "legobackgroundcolor.h"
#include "legofullscreenmovie.h"

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

private:
  char *m_savePath;
  undefined m_unk[20];
  LegoBackgroundColor *m_backgroundColor; // 0x18
  LegoBackgroundColor *m_tempBackgroundColor; // 0x1c
  LegoFullScreenMovie *m_fullScreenMovie; // 0x20
};

#endif // LEGOGAMESTATE_H
