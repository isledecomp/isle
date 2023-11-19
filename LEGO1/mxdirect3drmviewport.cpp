#include "mxdirect3drmviewport.h"

#include "decomp.h"

#include <math.h>

DECOMP_SIZE_ASSERT(IMxDirect3DRMViewport, 0x4);
DECOMP_SIZE_ASSERT(MxDirect3DRMViewport, 0x8);

struct MxDirect3DRMViewportData
{
  IDirect3DRMFrame *m_pDirect3DRMFrame;
  IDirect3DRMFrame *m_pCamera;
  IDirect3DRMFrame *m_pCameraParent;
  float m_backgroundRGB[3];
};

// OFFSET: LEGO1 0x100a2d80
IUnknown **MxDirect3DRMViewport::GetHandle()
{
  return (IUnknown**)&m_pDirect3DRMViewport;
}

// OFFSET: LEGO1 0x100a2d90
int MxDirect3DRMViewport::AddLight(MxDirect3DRMFrame *p_frame)
{
  IDirect3DRMFrame *frame = p_frame->GetFrame();
  return SUCCEEDED(GetViewportData()->m_pDirect3DRMFrame->AddChild(frame));
}

// OFFSET: LEGO1 0x100a2dc0
int MxDirect3DRMViewport::DeleteLight(MxDirect3DRMFrame *p_frame)
{
  IDirect3DRMFrame *frame = p_frame->GetFrame();
  return SUCCEEDED(GetViewportData()->m_pDirect3DRMFrame->DeleteChild(frame));
}

// Disassembly is not close, not sure what's going wrong.
// OFFSET: LEGO1 0x100a2df0
int MxDirect3DRMViewport::SetCamera(MxDirect3DRMFrame *p_camera)
{
  IDirect3DRMViewport *viewport = GetViewport();
  IDirect3DRMFrame *camera = p_camera->GetFrame();
  MxDirect3DRMViewportData* data = GetViewportData();
  if (data->m_pCameraParent)
  {
    data->m_pCameraParent->DeleteChild(data->m_pCamera);
    // Another call goes here, not sure what.
    data->m_pCameraParent->Release();
  }
  data->m_pCamera = camera;
  data->m_pCameraParent = NULL;
  return SUCCEEDED(viewport->SetCamera(camera));
}

// OFFSET: LEGO1 0x100a2e70
int MxDirect3DRMViewport::SetProjection(int p_type)
{
  D3DRMPROJECTIONTYPE proj;
  switch (p_type)
  {
  case 0:
    proj = D3DRMPROJECT_PERSPECTIVE;
    break;
  case 1:
    proj = D3DRMPROJECT_ORTHOGRAPHIC;
    break;
  default:
    proj = D3DRMPROJECT_PERSPECTIVE;
  }
  return SUCCEEDED(GetViewport()->SetProjection(proj));
}

// OFFSET: LEGO1 0x100a2eb0
int MxDirect3DRMViewport::SetPlanes(float p_near, float p_far, float p_FoV)
{
  int ret;
  float field = tanf(((p_FoV * 0.5f) * (5/9)) * 3.141592653589793);
  // Not very confident about this code, seems like p_near may actually be
  // multiplied by something before being passed to SetFront.
  if (ret = SUCCEEDED(m_pDirect3DRMViewport->SetFront(p_near)))
  {
    if (ret = SUCCEEDED(m_pDirect3DRMViewport->SetBack(p_far)))
    {
      ret = SUCCEEDED(m_pDirect3DRMViewport->SetField(field));
    }
  }
  return ret;
}

// OFFSET: LEGO1 0x100a2f30
int MxDirect3DRMViewport::SetBackgroundRGB(float p_r, float p_g, float p_b)
{
  int ret = TRUE;
  MxDirect3DRMViewportData* data = GetViewportData();
  data->m_backgroundRGB[0] = p_r;
  data->m_backgroundRGB[1] = p_g;
  data->m_backgroundRGB[2] = p_b;
  if (data->m_pCameraParent)
  {
    ret = data->m_pCameraParent->SetSceneBackgroundRGB(p_r, p_g, p_b) < 0 ? FALSE : TRUE;
  }
  return ret;
}

// OFFSET: LEGO1 0x100a2f80
int MxDirect3DRMViewport::GetBackgroundRGB(float *p_r, float *p_g, float *p_b)
{
  MxDirect3DRMViewportData* data = GetViewportData();
  *p_r = data->m_backgroundRGB[0];
  *p_g = data->m_backgroundRGB[1];
  *p_b = data->m_backgroundRGB[2];
  return TRUE;
}

// OFFSET: LEGO1 0x100a2fb0
int MxDirect3DRMViewport::Clear()
{
  return SUCCEEDED(m_pDirect3DRMViewport->Clear());
}

// OFFSET: LEGO1 0x100a2fd0 SetCameraParent
int MxDirect3DRMViewport::SetCameraParent(MxDirect3DRMFrame *p_frame)
{
  // Not close yet due to missing calls below.
  IDirect3DRMViewport* viewport = GetViewport();
  IDirect3DRMFrame* newParent = p_frame->GetFrame();
  MxDirect3DRMViewportData* data = GetViewportData();
  IDirect3DRMFrame *oldParent = data->m_pCameraParent;
  if (newParent != oldParent)
  {
    if (oldParent != NULL)
    {
      oldParent->DeleteChild(data->m_pCamera);
      // Another call goes here, not sure what.
      oldParent->Release();
    }
    data->m_pCameraParent = newParent;
    oldParent = data->m_pDirect3DRMFrame;
    if (newParent != NULL)
    {
      newParent->SetSceneBackgroundRGB(data->m_backgroundRGB[0], data->m_backgroundRGB[1], data->m_backgroundRGB[2]);
      newParent->AddChild(data->m_pCamera);
      // Another call goes here, not sure what.
      newParent->AddRef();
    }
  }
  return SUCCEEDED(viewport->Render(newParent));
}

// OFFSET: LEGO1 0x100a3080
int MxDirect3DRMViewport::ForceUpdate(int x, int y, int width, int height)
{
  return SUCCEEDED(m_pDirect3DRMViewport->ForceUpdate(x, y, x + width - 1, y + height - 1));
}

// OFFSET: LEGO1 0x100a30f0 Transform
int MxDirect3DRMViewport::Transform(float *p_shiftByVector3, float *p_out)
{
  D3DVECTOR s;
  s.x = p_shiftByVector3[0];
  s.y = p_shiftByVector3[1];
  s.z = p_shiftByVector3[2];

  D3DRMVECTOR4D d;
  int ret = m_pDirect3DRMViewport->Transform(&d, &s);
  if (SUCCEEDED(ret) == TRUE)
  {
    p_out[0] = d.x;
    p_out[1] = d.y;
    p_out[2] = d.z;
    p_out[3] = d.w;
  }
  return SUCCEEDED(ret);
}


// Don't know the types of the parameters for this.
// OFFSET: LEGO1 0x100a30c0
int MxDirect3DRMViewport::unk(int p_1, int p_2, int p_3, int p_4, int p_5, int p_6)
{
  return unkInternal(m_pDirect3DRMViewport, p_1, p_2, p_3, p_4, p_5, p_6);
}

// OFFSET: LEGO1 0x100a1290
int MxDirect3DRMViewport::unkInternal(IDirect3DRMViewport* p_viewport, int p_1, int p_2, int p_3, int p_4, int p_5, int p_6)
{
  return 0;
}
