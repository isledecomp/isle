#ifndef MXCRITICALSECTION_H
#define MXCRITICALSECTION_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

class MxCriticalSection
{
public:
  __declspec(dllexport) MxCriticalSection();
  __declspec(dllexport) ~MxCriticalSection();
  __declspec(dllexport) static void SetDoMutex();
  void Enter();
  void Leave();

private:
  CRITICAL_SECTION m_criticalSection;
  HANDLE m_mutex;
};

#endif // MXCRITICALSECTION_H
