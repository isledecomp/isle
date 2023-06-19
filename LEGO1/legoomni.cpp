#include "legoomni.h"

LegoOmni *LegoOmni::m_instance = NULL;

// OFFSET: LEGO1 0x1005ad10
LegoOmni *LegoOmni::GetInstance()
{
  return m_instance;
}

// OFFSET: LEGO1 0x10015700
LegoOmni *Lego()
{
  return LegoOmni::GetInstance();
}

// OFFSET: LEGO1 0x10015720
LegoVideoManager *VideoManager()
{
  return LegoOmni::GetInstance()->GetVideoManager();
}
