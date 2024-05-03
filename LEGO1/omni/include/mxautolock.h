#ifndef MXAUTOLOCK_H
#define MXAUTOLOCK_H

class MxCriticalSection;

#define AUTOLOCK(CS) MxAutoLock lock(&CS)

class MxAutoLock {
public:
	MxAutoLock(MxCriticalSection* p_criticalSection);
	~MxAutoLock();

private:
	MxCriticalSection* m_criticalSection;
};

#endif // MXAUTOLOCK_H
