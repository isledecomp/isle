#include "legoomni.h"

LegoOmni *LegoOmni::m_instance = NULL;

LegoOmni *LegoOmni::GetInstance()
{
  return m_instance;
}

LegoOmni *Lego()
{
  return LegoOmni::GetInstance();
}