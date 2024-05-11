#ifndef _MxStopWatch_h
#define _MxStopWatch_h

#include "assert.h"

#include <limits.h> // ULONG_MAX
#include <math.h>
#include <windows.h>

//////////////////////////////////////////////////////////////////////////////
//
// MxStopWatch
//
// NOTE:	MxStopWatch measures elapsed (wall clock) time.
//

#define HUGE_VAL_IMMEDIATE 1.7976931348623157e+308

// SIZE 0x18
class MxStopWatch {
public:
	MxStopWatch();
	~MxStopWatch() {}

	void Start();
	void Stop();
	void Reset();

	double ElapsedSeconds() const;

protected:
	unsigned long TicksPerSeconds() const;

private:
	LARGE_INTEGER m_startTick; // 0x00
	// ??? when we provide LARGE_INTEGER arithmetic, use a
	//     LARGE_INTEGER m_elapsedTicks rather than m_elapsedSeconds
	double m_elapsedSeconds;         // 0x0c
	unsigned long m_ticksPerSeconds; // 0x14
};

// FUNCTION: BETA10 0x100d8ba0
inline MxStopWatch::MxStopWatch()
{
	Reset();
	m_ticksPerSeconds = TicksPerSeconds();
}

// FUNCTION: BETA10 0x100d8be0
inline void MxStopWatch::Start()
{
	QueryPerformanceCounter(&m_startTick);
}

// FUNCTION: BETA10 0x100d8f50
inline void MxStopWatch::Stop()
{
	LARGE_INTEGER endTick;
	BOOL result;

	result = QueryPerformanceCounter(&endTick);
	assert(result);

	if (endTick.HighPart != m_startTick.HighPart) {
		// LARGE_INTEGER arithmetic not yet provided
		m_elapsedSeconds = HUGE_VAL_IMMEDIATE;
	}
	else {
		m_elapsedSeconds += ((endTick.LowPart - m_startTick.LowPart) / (double) m_ticksPerSeconds);
	}
}

// FUNCTION: BETA10 0x100d8c10
inline void MxStopWatch::Reset()
{
	m_startTick.LowPart = 0;
	m_startTick.HighPart = 0;
	m_elapsedSeconds = 0;
}

// FUNCTION: BETA10 0x100d8c60
inline unsigned long MxStopWatch::TicksPerSeconds() const
{
	LARGE_INTEGER ticksPerSeconds;
	BOOL result;

	result = QueryPerformanceFrequency(&ticksPerSeconds);
	assert(result);

	if (ticksPerSeconds.HighPart) {
		// LARGE_INTEGER arithmetic not yet provided

		// timer is too fast (faster than 32bits/s, i.e. faster than 4GHz)
		return ULONG_MAX;
	}
	else {
		return ticksPerSeconds.LowPart;
	}
}

// FUNCTION: BETA10 0x100d9020
inline double MxStopWatch::ElapsedSeconds() const
{
	return m_elapsedSeconds;
}

// SYNTHETIC: LEGO1 0x100a6fc0
// SYNTHETIC: BETA10 0x100d8e70
// MxStopWatch::~MxStopWatch

//////////////////////////////////////////////////////////////////////////////
//
// MxFrequencyMeter
//

// SIZE 0x20
class MxFrequencyMeter {
public:
	MxFrequencyMeter();

	void StartOperation();
	void EndOperation();
	double Frequency() const;
	void Reset();

	unsigned long OperationCount() const;
	double ElapsedSeconds() const;

	void IncreaseOperationCount(unsigned long);

private:
	unsigned long m_operationCount; // 0x00
	MxStopWatch m_stopWatch;        // 0x08
};

//////////////////////////////////////////////////////////////////////////////
//
// MxFrequencyMeter implementation
//

// FUNCTION: BETA10 0x1017dd80
inline MxFrequencyMeter::MxFrequencyMeter() : m_operationCount(0)
{
}

// FUNCTION: BETA10 0x1017deb0
inline void MxFrequencyMeter::StartOperation()
{
	m_stopWatch.Start();
}

// FUNCTION: BETA10 0x1017df10
inline void MxFrequencyMeter::EndOperation()
{
	m_stopWatch.Stop();
	m_operationCount++;
}

inline double MxFrequencyMeter::Frequency() const
{
	double elapsedSeconds = m_stopWatch.ElapsedSeconds();

	if (elapsedSeconds > 0) {
		return m_operationCount / elapsedSeconds;
	}
	else {
		if (m_operationCount) {
			// operations performed - no time elapsed
			return HUGE_VAL;
		}
		else {
			// no operations performed - no time elapsed
			return 0;
		}
	}
}

// FUNCTION: BETA10 0x1017dee0
inline void MxFrequencyMeter::Reset()
{
	m_stopWatch.Reset();
	m_operationCount = 0;
}

inline unsigned long MxFrequencyMeter::OperationCount() const
{
	return m_operationCount;
}

// FUNCTION: BETA10 0x1017df40
inline void MxFrequencyMeter::IncreaseOperationCount(unsigned long delta)
{
	m_operationCount += delta;
}

// FUNCTION: BETA10 0x1017df60
inline double MxFrequencyMeter::ElapsedSeconds() const
{
	return m_stopWatch.ElapsedSeconds();
}

// SYNTHETIC: LEGO1 0x100abd10
// SYNTHETIC: BETA10 0x1017de40
// MxFrequencyMeter::~MxFrequencyMeter

#endif /* _MxStopWatch_h */
