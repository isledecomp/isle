#include "mxstreamcontroller.h"

#include "mxautolocker.h"

// OFFSET: LEGO1 0x100c0b90 STUB
MxStreamController::MxStreamController()
{
  // TODO
}

// OFFSET: LEGO1 0x100c1290 STUB
MxStreamController::~MxStreamController()
{
  // TODO
}

// OFFSET: LEGO1 0x100c20d0 STUB
MxBool MxStreamController::FUN_100c20d0(MxDSObject &p_obj)
{
  // TODO
  return TRUE;
}

// OFFSET: LEGO1 0x100c1520
MxResult MxStreamController::Open(const char *p_filename)
{
  MxAutoLocker locker(&m_criticalSection);

  // TODO

  return SUCCESS;
}

// OFFSET: LEGO1 0x100b9400
undefined4 MxStreamController::vtable0x18(undefined4 p_unknown, undefined4 p_unknown2)
{
  return -1;
}

// OFFSET: LEGO1 0x100b9410
undefined4 MxStreamController::vtable0x1C(undefined4 p_unknown, undefined4 p_unknown2)
{
  return -1;
}

// OFFSET: LEGO1 0x100c1690 STUB
long MxStreamController::vtable0x20(MxDSAction* action)
{
  // TODO STUB
  return -1;
}
