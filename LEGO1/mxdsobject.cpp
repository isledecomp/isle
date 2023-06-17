#include "mxdsobject.h"

#include <string.h>
#include <stdlib.h>

void MxDSObject::SetObjectName(const char *p_name)
{
  // TODO: instead of the expected CMP EAX,ESI we get CMP ESI,EAX
  if (p_name != this->m_name)
  {
    free(this->m_name);

    if (p_name) {
      this->m_name = (char *)malloc(strlen(p_name) + 1);

      if (this->m_name) {
        strcpy(this->m_name, p_name);
      }
    }
    else {
      this->m_name = NULL;
    }
  }
}

