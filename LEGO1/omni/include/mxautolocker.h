#ifndef MXAUTOLOCKER_H
#define MXAUTOLOCKER_H

#include "mxcriticalsection.h"

#define AUTOLOCK(CS) MxAutoLocker lock(&CS);

class MxAutoLocker {
public:
	MxAutoLocker(MxCriticalSection* p_criticalSection);
	~MxAutoLocker();

private:
	MxCriticalSection* m_criticalSection;
};

#endif // MXAUTOLOCKER_H
