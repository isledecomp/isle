#ifndef MXBACKGROUNDAUDIOMANAGER_H
#define MXBACKGROUNDAUDIOMANAGER_H

#include "mxcore.h"

class MxBackgroundAudioManager : public MxCore
{
public:
  __declspec(dllexport) void Enable(unsigned char p);
};

#endif // MXBACKGROUNDAUDIOMANAGER_H
