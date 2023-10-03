#ifndef MXRAMSTREAMCONTROLLER_H
#define MXRAMSTREAMCONTROLLER_H

#include "mxdsbuffer.h"
#include "mxstreamcontroller.h"

// VTABLE 0x100dc728
// SIZE 0x98
class MxRAMStreamController : public MxStreamController
{
public:
  inline MxRAMStreamController() {}

private:
  MxDSBuffer m_buffer;

};

#endif // MXRAMSTREAMCONTROLLER_H
