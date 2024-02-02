#ifndef MXSCHEDULER_H
#define MXSCHEDULER_H

#include "mxtypes.h"

class MxScheduler {
public:
	static MxScheduler* GetInstance();
	void StartMultiTasking(MxULong);
};

#endif // MXSCHEDULER_H
