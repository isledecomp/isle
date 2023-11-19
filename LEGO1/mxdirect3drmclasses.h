
#include "mxdirect3drmobject.h"

// VTABLE 0x100dbae8
class IMxDirect3DRMFrame : public IMxDirect3DRMObject
{
public:
  virtual ~IMxDirect3DRMFrame() {}

  virtual IUnknown **GetHandle() = 0;

  // vtable + 0x08
  virtual int AddTransform(D3DRMMATRIX4D *p_matrix, D3DVECTOR *p_oldPosition) = 0;
};

// VTABLE 0x100dbad8
class MxDirect3DRMFrame : IMxDirect3DRMFrame
{
public:
  MxDirect3DRMFrame() {}
  virtual ~MxDirect3DRMFrame() {}

  virtual IUnknown **GetHandle();
  IDirect3DRMFrame *GetFrame() { return m_pDirect3DRMFrame; }

  // vtable + 0x08
  // Not 100% confident on this function signature
  virtual int AddTransform(D3DRMMATRIX4D *p_matrix, D3DVECTOR *p_oldPosition);

private:
  IDirect3DRMFrame *m_pDirect3DRMFrame;
};

// VTABLE 0x100dbb08
class IMxDirect3DRMLight : public IMxDirect3DRMObject
{
public:
  virtual ~IMxDirect3DRMLight() {}

  virtual IUnknown **GetHandle() = 0;

  // vtable+0x08
  virtual int AddTransform(D3DRMMATRIX4D *p_matrix) = 0;
  virtual int SetColorRGB(float p_r, float p_g, float p_b) = 0;
};

// VTABLE 0x100dbaf8
class MxDirect3DRMLight : public IMxDirect3DRMLight
{
public:
  MxDirect3DRMLight() {}
  virtual ~MxDirect3DRMLight() {}

  virtual IUnknown **GetHandle();

  // vtable+0x08
  // Not 100% confident on this function signature
  virtual int AddTransform(D3DRMMATRIX4D *p_matrix);
  virtual int SetColorRGB(float p_r, float p_g, float p_b);

private:
  IDirect3DRMFrame *m_pFrameWithLight;
};

// VTABLE 0x100dbb30
class IMxDirect3DRMMesh : public IMxDirect3DRMObject
{
public:
  virtual ~IMxDirect3DRMMesh() {}

  virtual IUnknown **GetHandle() = 0;

  // vtable+0x08
  virtual int SetMeshData(int p_faceCount, int p_vertexCount, void *p_positions, void *p_normals, void *p_uvs, int p_unk1, int *p_unk2) = 0;
  virtual int GetBox(float *p_minVec3, float *p_maxVec3) = 0;
  virtual IMxDirect3DRMMesh *Clone() = 0;
};

// VTABLE 0x100dbb18
class MxDirect3DRMMesh : public IMxDirect3DRMMesh
{
public:
  MxDirect3DRMMesh() : m_pDirect3DRMMesh(NULL) {}
  virtual ~MxDirect3DRMMesh() {}

  virtual IUnknown **GetHandle();

  // vtable+0x08
  virtual int SetMeshData(int p_faceCount, int p_vertexCount, void *p_positions, void *p_normals, void *p_uvs, int p_unk1, int *p_unk2);
  virtual int GetBox(float *p_minVec3, float *p_maxVec3);
  virtual IMxDirect3DRMMesh *Clone();

private:
  IDirect3DRMMesh *m_pDirect3DRMMesh;
};