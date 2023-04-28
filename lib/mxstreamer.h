#ifndef MXSTREAMER_H
#define MXSTREAMER_H

#include "mxstreamcontroller.h"

class MxStreamer
{
public:
  __declspec(dllexport) MxStreamController *Open(const char *name, unsigned short p);
  __declspec(dllexport) long Close(const char *p);

};

#endif // MXSTREAMER_H
