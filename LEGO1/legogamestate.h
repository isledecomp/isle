#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

#include "mxtypes.h"

class LegoGameState
{
public:
  __declspec(dllexport) LegoGameState();
  __declspec(dllexport) ~LegoGameState();
  __declspec(dllexport) MxResult Load(MxULong);
  __declspec(dllexport) MxResult Save(MxULong p);
  __declspec(dllexport) void SerializePlayersInfo(short p);
  __declspec(dllexport) void SerializeScoreHistory(short p);
  __declspec(dllexport) void SetSavePath(char *p);
};

#endif // LEGOGAMESTATE_H
