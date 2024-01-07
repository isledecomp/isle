#ifndef MXSCHEDULER_H
#define MXSCHEDULER_H

#include "mxtypes.h"

class MxScheduler {
public:
	__declspec(dllexport) static MxScheduler* GetInstance();
	__declspec(dllexport) void StartMultiTasking(MxULong);
};

#endif // MXSCHEDULER_H
