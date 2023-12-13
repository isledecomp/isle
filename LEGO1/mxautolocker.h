#ifndef MXAUTOLOCKER_H
#define MXAUTOLOCKER_H

#include "mxcriticalsection.h"

class MxAutoLocker {
public:
	MxAutoLocker(MxCriticalSection* p_criticalSection);
	~MxAutoLocker();

private:
	MxCriticalSection* m_criticalSection;
};

#endif // MXAUTOLOCKER_H
