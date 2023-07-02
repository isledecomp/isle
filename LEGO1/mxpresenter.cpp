#include "mxpresenter.h"

#include "decomp.h"

DECOMP_SIZE_ASSERT(MxPresenter, 0x40);

// OFFSET: LEGO1 0x1000bee0 STUB
void MxPresenter::DoneTickle()
{
  // TODO
}

// OFFSET: LEGO1 0x100b4d50
void MxPresenter::Init()
{
  m_unk0x8 = 0;
  m_action = NULL;
  m_unk0x18 = 0;
  m_unk0x3c = 0;
  m_unk0xc = 0;
  m_unk0x10 = 0;
  m_unk0x14 = 0;
}

// OFFSET: LEGO1 0x100b4fc0 STUB
void MxPresenter::ParseExtra()
{
  // TODO
}

// OFFSET: LEGO1 0x1000bf00
MxPresenter::~MxPresenter()
{
}

// OFFSET: LEGO1 0x100b5200 STUB
MxLong MxPresenter::Tickle()
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100b4d80 STUB
MxLong MxPresenter::StartAction(MxStreamController *, MxDSAction *)
{
  // TODO

  return 0;
}

// OFFSET: LEGO1 0x100b4e40 STUB
void MxPresenter::EndAction()
{
  // TODO
}

// OFFSET: LEGO1 0x100b52d0 STUB
void MxPresenter::Enable(unsigned char)
{
  // TODO
}

// OFFSET: LEGO1 0x1000be30
void MxPresenter::VTable0x14()
{
}

// OFFSET: LEGO1 0x1000be40
void MxPresenter::VTable0x18()
{
  ParseExtra();
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 2;
}

// OFFSET: LEGO1 0x1000be60
void MxPresenter::VTable0x1c()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 3;
}

// OFFSET: LEGO1 0x1000be80
void MxPresenter::VTable0x20()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 4;
}

// OFFSET: LEGO1 0x1000bea0
void MxPresenter::VTable0x24()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 5;
}

// OFFSET: LEGO1 0x1000bec0
void MxPresenter::VTable0x28()
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = 6;
}

// OFFSET: LEGO1 0x1000bf70
undefined4 MxPresenter::VTable0x34()
{
  return 0;
}

// OFFSET: LEGO1 0x1000bf80
void MxPresenter::InitVirtual()
{
  Init();
}
// OFFSET: LEGO1 0x1000bf90
void MxPresenter::VTable0x44(undefined4 param)
{
  m_unk0xc |= 1 << (unsigned char)m_unk0x8;
  m_unk0x8 = param;
}

// OFFSET: LEGO1 0x1000bfb0
unsigned char MxPresenter::VTable0x48(unsigned char param)
{
  return m_unk0xc & (1 << param);
}

// OFFSET: LEGO1 0x1000bfc0
undefined4 MxPresenter::VTable0x4c()
{
  return 0;
}

// OFFSET: LEGO1 0x1000bfd0
undefined MxPresenter::VTable0x50(undefined4, undefined4)
{
  return 0;
}
