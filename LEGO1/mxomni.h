#ifndef MXOMNI_H
#define MXOMNI_H

#include "mxresult.h"
#include "mxomnicreateparam.h"
#include "mxomnicreateflags.h"
#include "mxtimer.h"

class MxOmni
{
public:
  __declspec(dllexport) static void DestroyInstance();
  __declspec(dllexport) static const char *GetCD();
  __declspec(dllexport) static const char *GetHD();
  __declspec(dllexport) static MxOmni *GetInstance();
  __declspec(dllexport) static unsigned char IsSound3D();
  __declspec(dllexport) static void SetCD(const char *s);
  __declspec(dllexport) static void SetHD(const char *s);
  __declspec(dllexport) static void SetSound3D(unsigned char);
  
  MxResult MxOmni::Create(const MxOmniCreateParam &p);

  MxTimer* GetTimer() const { return this->m_Timer; } 

private:
  char padding[0x3c];
  MxTimer* m_Timer;
};

#endif // MXOMNI_H
