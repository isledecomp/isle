#include "mxmediapresenter.h"

// 0x100f074c
static char* g_mxMediaPresenterClassName = "MxMediaPresenter";

// OFFSET: LEGO1 0x100d4ce0
long MxMediaPresenter::Tickle()
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100d4ce4
const char *MxMediaPresenter::GetClassName() const
{
  return g_mxMediaPresenterClassName;
}

// OFFSET: LEGO1 0x1000c5d0
MxBool MxMediaPresenter::IsClass(const char *name) const
{
  // TODO

  return MxBool();
}

// OFFSET: LEGO1 0x100b5d90
void MxMediaPresenter::VTable0x20()
{
  // TODO
}

// OFFSET: LEGO1 0x100b5e10
unsigned int MxMediaPresenter::VTable0x24()
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100b5ef0
void MxMediaPresenter::DoneTickle()
{
  // TODO
}

// OFFSET: LEGO1 0x100b5700
long MxMediaPresenter::StartAction(MxStreamController *, MxDSAction *)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100b5bc0
void MxMediaPresenter::EndAction()
{
  // TODO
}

// OFFSET: LEGO1 0x100b6030
void MxMediaPresenter::Enable(unsigned char param)
{
  // TODO
}
