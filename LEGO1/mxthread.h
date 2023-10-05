#ifndef MXTHREAD_H
#define MXTHREAD_H

#include "compat.h"
#include "mxtypes.h"
#include "mxsemaphore.h"

class MxCore;

class MxThread
{
public:
  // Note: Comes before virtual destructor
  virtual MxResult Run();

  MxResult Start(int p_stack, int p_flag);

  void Terminate();

  void Sleep(MxS32 p_milliseconds);

  // Inferred, not in DLL
  inline MxBool IsRunning() { return m_running; }

protected:
  MxThread();

public:
  virtual ~MxThread();

private:
  static unsigned ThreadProc(void *p_thread);

  MxULong m_hThread;
  MxU32 m_threadId;
  MxBool m_running;
  MxSemaphore m_semaphore;
};

class MxTickleThread : public MxThread
{
public:
  MxTickleThread(MxCore *p_target, int p_frequencyMS);

  // Unclear at this time whether this function and the m_target field are
  // actually a general "userdata" pointer in the base MxThread, but it seems
  // like the only usage is with an MxTickleThread.
  MxResult StartWithTarget(MxCore* p_target);

  // Only inlined, no offset
  virtual ~MxTickleThread() {}

  MxResult Run() override;

private:
  MxCore *m_target;
  MxS32 m_frequencyMS;
};

#endif // MXTHREAD_H
