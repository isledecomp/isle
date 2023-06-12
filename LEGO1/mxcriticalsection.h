#ifndef MXCRITICALSECTION_H
#define MXCRITICALSECTION_H

class MxCriticalSection
{
public:
  __declspec(dllexport) MxCriticalSection();
  __declspec(dllexport) ~MxCriticalSection();
  __declspec(dllexport) static void SetDoMutex();
};

#endif // MXCRITICALSECTION_H
