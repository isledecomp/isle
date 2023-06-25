#include "legobackgroundcolor.h"
#include "legoomni.h"
#include "legoutil.h"
#include "legovideomanager.h"
const char *Delimiter = "\t";
const char *set = "set";
const char *reset = "reset";
// OFFSET: LEGO1 0x1003bfb0
LegoBackgroundColor::LegoBackgroundColor(const char *name, const char *colorString)
{
  this->m_name.operator=(name);
  this->m_name.ToUpperCase();
  SetColorString(colorString);
}

// OFFSET: LEGO1 0x1003c070
void LegoBackgroundColor::SetColorString(const char *colorString)
{

  m_colorString.operator=(colorString);
  m_colorString.ToLowerCase();

  float converted_b;
  float converted_g;
  float converted_r;
  LegoVideoManager *videomanager = VideoManager();

  if (videomanager && colorString)
  {
    int length = strlen(colorString) + 1;
    char *colorStringCopy = (char *)malloc(length);
    strcpy(colorStringCopy, colorString);
    char *colorStringSplit = strtok(colorStringCopy, Delimiter);
    if (!strcmp(colorStringSplit, set))
    {
      // set it

      //TODO: I think this is in BGR because of the order of local variables
      char *blue = strtok(0, Delimiter);
      if (blue)
        b = atoi(blue) * 0.01;
      char *green = strtok(0, Delimiter);
      if (green)
        g = atoi(green) * 0.01;
      char *red = strtok(0, Delimiter);
      if (red)
        r = atoi(red) * 0.01;
    }
    else if (!strcmp(colorStringSplit, reset))
    {
      // reset it

      ConvertColor(this->b, this->g, this->r, &converted_b, &converted_g, &converted_r);
      videomanager->SetSkyColor(converted_b, converted_g, converted_r);
    }
    free(colorStringCopy);
  }
}