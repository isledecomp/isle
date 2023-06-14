#include "mxomni.h"

MxOmni* MxOmni::m_instance = NULL;

MxOmni *MxOmni::GetInstance()
{
  return m_instance;
}