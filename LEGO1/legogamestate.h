#ifndef LEGOGAMESTATE_H
#define LEGOGAMESTATE_H

class LegoGameState
{
public:
  __declspec(dllexport) LegoGameState();
  __declspec(dllexport) ~LegoGameState();
  __declspec(dllexport) long Load(unsigned long);
  __declspec(dllexport) long Save(unsigned long p);
  __declspec(dllexport) void SerializePlayersInfo(short p);
  __declspec(dllexport) void SerializeScoreHistory(short p);
  __declspec(dllexport) void SetSavePath(char *p);
};

#endif // LEGOGAMESTATE_H
