#include "legotesttimer.h"

#include "legoeventnotificationparam.h"
#include "legoinputmanager.h"
#include "misc.h"
#include "mxnotificationparam.h"

#include <stdio.h>

// FUNCTION: BETA10 0x100d1030
LegoTestTimer::LegoTestTimer(LegoS32 p_numTimers, LegoS32 p_interval, LegoS32 p_numBins, LegoS32 p_type)
{
	m_enable = FALSE;
	m_keyRegistered = FALSE;

	if (p_interval > 0) {
		m_numTimers = p_numTimers;
		m_interval = p_interval;
		m_numBins = p_numBins / m_interval;

		m_lastTime = new LegoS32[m_numTimers];
		m_totalTime = new LegoS32[m_numTimers];
		m_timers = new LegoS32*[m_numTimers];

		for (int i = 0; i < m_numTimers; i++) {
			m_lastTime[i] = -1;
			m_timers[i] = new LegoS32[m_numBins];
			for (int j = 0; j < m_numBins; j++) {
				m_timers[i][j] = 0;
			}
		}
	}
	else {
		m_numTimers = 0;
		m_interval = 0;
		m_numBins = 0;
		m_lastTime = NULL;
		m_totalTime = NULL;
		m_timers = NULL;
	}
}

// FUNCTION: BETA10 0x100d11ee
LegoTestTimer::~LegoTestTimer()
{
	if (m_keyRegistered && InputManager()) {
		InputManager()->UnRegister(this);
	}

	m_enable = FALSE;
	if (m_numTimers != 0) {
		delete[] m_lastTime;
		delete[] m_totalTime;

		for (int i = 0; i < m_numTimers; i++) {
			delete m_timers[i];
		}

		delete[] m_timers;
	}
}

// FUNCTION: BETA10 0x100d132c
void LegoTestTimer::Tick(LegoS32 p_timer)
{
	if (m_enable) {
		MxULong time = timeGetTime();
		LegoS32 prev = p_timer ? p_timer - 1 : 0;
		if (m_lastTime[p_timer] == -1) {
			m_lastTime[p_timer] = time;
			m_totalTime[p_timer] = 0;

			for (int i = 0; i < m_numBins; i++) {
				m_timers[p_timer][i] = 0;
			}
		}
		else {
			LegoS32 dtim = time - m_lastTime[prev];
			if (dtim < 0) {
				dtim = 0;
			}

			m_lastTime[p_timer] = time;
			LegoS32 local_14 = dtim / m_interval;
			if (local_14 >= m_numBins) {
				local_14 = m_numBins - 1;
			}

			m_timers[p_timer][local_14]++;
			m_totalTime[p_timer] += dtim;
		}
	}
	else if (!m_keyRegistered) {
		InputManager()->Register(this);
		m_keyRegistered = TRUE;
	}
}

// FUNCTION: BETA10 0x100d148f
void LegoTestTimer::Print()
{
	FILE* f = fopen("\\TEST_TIME.TXT", "w");
	if (f) {
		int i;

		fprintf(f, "timer");
		for (i = 0; i < m_numTimers; i++) {
			fprintf(f, "%8d ", i);
		}

		fprintf(f, "\n");
		for (int k = 0; k < m_numBins; k++) {
			fprintf(f, "%3d: ", m_interval * (k + 1));
			for (int j = 0; j < m_numTimers; j++) {
				fprintf(f, "%8d ", m_timers[j][k]);
			}
			fprintf(f, "\n");
		}

		fprintf(f, "ttime");
		for (i = 0; i < m_numTimers; i++) {
			fprintf(f, "%8d ", m_totalTime[i]);
		}

		fclose(f);
	}

	ResetAtNextTick();
}

// FUNCTION: BETA10 0x100d161e
void LegoTestTimer::ResetAtNextTick()
{
	for (int i = 0; i < m_numTimers; i++) {
		m_lastTime[i] = -1;
	}
}

// FUNCTION: BETA10 0x100d1667
MxLong LegoTestTimer::Notify(MxParam& p_param)
{
	if (((MxNotificationParam&) p_param).GetNotification() == c_notificationKeyPress) {
		MxU8 key = ((LegoEventNotificationParam&) p_param).GetKey();

		if (key == 's' || key == 'S') {
			ResetAtNextTick();
			m_enable = TRUE;
		}
		else if (key == 'p' || key == 'P') {
			m_enable = FALSE;
			Print();
		}
	}

	return 0;
}
