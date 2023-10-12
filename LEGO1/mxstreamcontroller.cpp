#include "mxstreamcontroller.h"

#include "mxautolocker.h"
#include "legoomni.h"

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
  char sourceName [256];
  MxAutoLocker locker(&m_criticalSection);

  MakeSourceName(sourceName, p_filename);
  this->atom = MxAtomId(sourceName, LookupMode_LowerCase2);
  return SUCCESS;
}

// OFFSET: LEGO1 0x100b9400
MxResult MxStreamController::vtable0x18(undefined4 p_unknown, undefined4 p_unknown2)
{
  return FAILURE;
}

// OFFSET: LEGO1 0x100b9410
MxResult MxStreamController::vtable0x1C(undefined4 p_unknown, undefined4 p_unknown2)
{
  return FAILURE;
}

// OFFSET: LEGO1 0x100c1690
MxResult MxStreamController::vtable0x20(MxDSAction* p_action)
{
  MxAutoLocker locker(&m_criticalSection);

  MxResult result;
  MxU32 offset = 0;

  MxS32 objectId = p_action->GetObjectId();
  MxStreamProvider *provider = m_provider;

  if ((MxS32) provider->GetLengthInDWords() > objectId)
    offset = provider->GetBufferForDWords()[objectId];

  if (offset)
    result = vtable0x2c(p_action, offset);
  else
    result = FAILURE;

  return result;
}

// OFFSET: LEGO1 0x100c1740 STUB
MxResult MxStreamController::vtable0x24(undefined4 p_unknown)
{
  // TODO STUB
  return FAILURE;
}

// OFFSET: LEGO1 0x100b9420
MxResult MxStreamController::vtable0x28()
{
  return SUCCESS;
}

// OFFSET: LEGO1 0x100c1c10 STUB
MxResult MxStreamController::vtable0x2c(MxDSAction* p_action, MxU32 p_bufferval)
{
  return FAILURE;
}

// OFFSET: LEGO1 0x100c1ce0 STUB
MxResult MxStreamController::vtable0x30(undefined4 p_unknown)
{
  return FAILURE;
}
