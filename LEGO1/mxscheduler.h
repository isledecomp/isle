#ifndef MXSCHEDULER_H
#define MXSCHEDULER_H

class MxScheduler
{
public:
  __declspec(dllexport) static MxScheduler *GetInstance();
  __declspec(dllexport) void StartMultiTasking(unsigned long);
};

#endif // MXSCHEDULER_H
