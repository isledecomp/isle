#ifndef LEGOVIDEOMANAGER_H
#define LEGOVIDEOMANAGER_H

class LegoVideoManager
{
public:
  __declspec(dllexport) int EnableRMDevice();

  __declspec(dllexport) void EnableFullScreenMovie(unsigned char a, unsigned char b);

  __declspec(dllexport) void MoveCursor(int x, int y);

};

#endif // LEGOVIDEOMANAGER_H
