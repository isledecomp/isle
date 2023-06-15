#include "mxstring.h"
#include <stdlib.h>
#include <string.h>

MxString::MxString()
{
  // Set string to one char in length and set that char to null terminator
  this->m_data = (char *)malloc(1);
  this->m_data[0] = 0;
  this->m_length = 0;
}

// TODO: this *mostly* matches, again weird with the comparison
const MxString &MxString::operator=(const char *param)
{
  if (this->m_data != param)
  {
    free(this->m_data);
    this->m_length = strlen(param);
    this->m_data = (char *)malloc(this->m_length + 1);
    strcpy(this->m_data, param);
  }

  return *this;
}

MxString::~MxString()
{
  free(this->m_data);
}
