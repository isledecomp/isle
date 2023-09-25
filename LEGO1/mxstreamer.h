#ifndef MXSTREAMER_H
#define MXSTREAMER_H

#include <list>

#include "decomp.h"
#include "mxcore.h"
#include "mxstreamcontroller.h"
#include "mxtypes.h"

// NOTE: This feels like some kind of templated class, maybe something from the
//       STL. But I haven't figured out what yet (it's definitely not a vector).
class MxStreamerSubClass1
{
public:
  inline MxStreamerSubClass1(undefined4 size);

  ~MxStreamerSubClass1() { delete [] m_buffer; }

  undefined4 GetSize() { return m_size; }

  void SetBuffer(undefined *p_buf) { m_buffer = p_buf; }

private:
  undefined *m_buffer;
  undefined4 m_size;
  undefined4 m_unk08;
};

class MxStreamerSubClass2 : public MxStreamerSubClass1
{
public:
  inline MxStreamerSubClass2() : MxStreamerSubClass1(0x40) {}
};

class MxStreamerSubClass3 : public MxStreamerSubClass1
{
public:
  inline MxStreamerSubClass3() : MxStreamerSubClass1(0x80) {}
};

// VTABLE 0x100dc710
// SIZE 0x2c
class MxStreamer : public MxCore
{
public:
  enum OpenMode
  {
    e_DiskStream,
    e_RAMStream
  };

  MxStreamer();
  virtual ~MxStreamer() override; // vtable+0x0

  __declspec(dllexport) MxStreamController *Open(const char *p_name, MxU16 p_openMode);
  __declspec(dllexport) MxLong Close(const char *p_name);

  virtual MxLong Notify(MxParam &p) override; // vtable+0x4

  // OFFSET: LEGO1 0x100b9000
  inline virtual const char *ClassName() const override // vtable+0x0c
  {
    // 0x1010210c
    return "MxStreamer";
  }

  // OFFSET: LEGO1 0x100b9010
  inline virtual MxBool IsA(const char *p_name) const override // vtable+0x10
  {
    return !strcmp(p_name, MxStreamer::ClassName()) || MxCore::IsA(p_name);
  }

  virtual MxResult Init(); // vtable+0x14

  MxStreamController *GetOpenStream(const char *p_name);

  MxResult AddStreamControllerToOpenList(MxStreamController *p_stream);

private:
  list<MxStreamController *> m_openStreams; // 0x8
  MxStreamerSubClass2 m_subclass1; // 0x14
  MxStreamerSubClass3 m_subclass2; // 0x20

};

#endif // MXSTREAMER_H
