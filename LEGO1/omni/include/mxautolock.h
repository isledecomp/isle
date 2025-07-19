#ifndef MXAUTOLOCK_H
#define MXAUTOLOCK_H

class MxCriticalSection;

#ifdef BETA10
#define AUTOLOCK(CS) MxAutoLock lock(&CS, __FILE__, __LINE__)
#else
#define AUTOLOCK(CS) MxAutoLock lock(&CS)
#endif

class MxAutoLock {
public:
#ifdef BETA10
	MxAutoLock(MxCriticalSection* p_criticalSection, const char* filename, int line);
#else
	MxAutoLock(MxCriticalSection* p_criticalSection);
#endif
	~MxAutoLock();

private:
	MxCriticalSection* m_criticalSection; // 0x00

#ifdef BETA10
	unsigned long m_currentThreadId; // 0x04
#endif
};

#endif // MXAUTOLOCK_H
