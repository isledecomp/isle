#include "legoomni.h"

// OFFSET: LEGO1 0x10058a00
LegoOmni::LegoOmni()
{
  Init();
}

// OFFSET: LEGO1 0x10058b50
LegoOmni::~LegoOmni()
{
  Destroy();
}

// OFFSET: LEGO1 0x1005ad10
LegoOmni *LegoOmni::GetInstance()
{
  return (LegoOmni *) m_instance;
}

// OFFSET: LEGO1 0x10015700
LegoOmni *Lego()
{
  return (LegoOmni *) MxOmni::GetInstance();
}

// OFFSET: LEGO1 0x10015720
LegoVideoManager *VideoManager()
{
  return LegoOmni::GetInstance()->GetVideoManager();
}

// OFFSET: LEGO1 0x100157f0
LegoBuildingManager *BuildingManager()
{
  return LegoOmni::GetInstance()->GetLegoBuildingManager();
}

// OFFSET: LEGO1 0x10015790
Isle *GetIsle()
{
  return LegoOmni::GetInstance()->GetIsle();
}

// OFFSET: LEGO1 0x100157e0
LegoPlantManager *PlantManager()
{
  return LegoOmni::GetInstance()->GetLegoPlantManager();
}

// OFFSET: LEGO1 0x1005b5f0
long LegoOmni::Notify(MxParam &p)
{
  // FIXME: Stub
  return 0;
}

// OFFSET: LEGO1 0x10058aa0
const char *LegoOmni::GetClassName() const
{
  return "LegoOmni";
}

// OFFSET: LEGO1 0x10058ab0
MxBool LegoOmni::IsClass(const char *name) const
{
  return strcmp("LegoOmni", name) == 0;
}

// OFFSET: LEGO1 0x10058bd0
void LegoOmni::Init()
{
  // FIXME: Stub
}

// OFFSET: LEGO1 0x10058e70
MxResult LegoOmni::Create(MxOmniCreateParam &p)
{
  // FIXME: Stub
  return SUCCESS;
}

void LegoOmni::Destroy()
{
  // FIXME: Stub
}

void LegoOmni::vtable20()
{
  // FIXME: Stub
}

void LegoOmni::vtable24(MxDSAction &ds)
{
  // FIXME: Stub
}

MxBool LegoOmni::vtable28(MxDSAction &ds)
{
  // FIXME: Stub
  return MX_TRUE;
}

void LegoOmni::vtable2c()
{
  // FIXME: Stub
}

void LegoOmni::vtable30()
{
  // FIXME: Stub
}

void LegoOmni::vtable34()
{
  // FIXME: Stub
}

void LegoOmni::vtable38()
{
  // FIXME: Stub
}

void LegoOmni::vtable3c()
{
  // FIXME: Stub
}

unsigned char LegoOmni::vtable40()
{
  // FIXME: Stub
  return 0;
}
