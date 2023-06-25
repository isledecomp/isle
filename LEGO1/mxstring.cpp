#include "mxstring.h"
#include <stdlib.h>
#include <string.h>

// OFFSET: LEGO1 0x100ae200
MxString::MxString()
{
  // Set string to one char in length and set that char to null terminator
  this->m_data = (char *)malloc(1);
  this->m_data[0] = 0;
  this->m_length = 0;
}

// OFFSET: LEGO1 0x100ae2a0
MxString::MxString(const MxString &str)
{
  this->m_length = str.m_length;
  this->m_data = (char *)malloc(this->m_length + 1);
  strcpy(this->m_data, str.m_data);
}

// OFFSET: LEGO1 0x100ae350
MxString::MxString(const char *str)
{
  if (str) {
    this->m_length = strlen(str);
    this->m_data = (char *)malloc(this->m_length + 1);
    strcpy(this->m_data, str);
  } else {
    this->m_data = (char *)malloc(1);
    this->m_data[0] = 0;
    this->m_length = 0;
  }
}

// OFFSET: LEGO1 0x100ae420
MxString::~MxString()
{
  free(this->m_data);
}

// OFFSET: LEGO1 0x100ae490
void MxString::ToUpperCase()
{
  strupr(this->m_data);
}

// OFFSET: LEGO1 0x100ae4a0
void MxString::ToLowerCase()
{
  strlwr(this->m_data);
}

// OFFSET: LEGO1 0x100ae4b0
const MxString &MxString::operator=(MxString *param)
{
  if (this->m_data != param->m_data)
  {
    free(this->m_data);
    this->m_length = param->m_length;
    this->m_data = (char *)malloc(this->m_length + 1);
    strcpy(this->m_data, param->m_data);
  }

  return *this;
}

// TODO: this *mostly* matches, again weird with the comparison
// OFFSET: LEGO1 0x100ae510
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
