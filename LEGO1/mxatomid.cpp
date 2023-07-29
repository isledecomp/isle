#include "mxatomid.h"
#include "mxomni.h"

// OFFSET: LEGO1 0x100acf90
MxAtomId::MxAtomId(const char *p_str, LookupMode p_mode)
{
  if (!MxOmni::GetInstance())
    return;

  if (!AtomIdTree())
    return;

  TreeValue *value = try_to_open(p_str, p_mode);
  m_internal = value->m_str.GetData();
  value->RefCountInc();
}

// OFFSET: LEGO1 0x100acfd0
MxAtomId::~MxAtomId()
{
  Destroy();
}

// OFFSET: LEGO1 0x100acfe0
void MxAtomId::Destroy()
{
  if (*m_internal == '\0')
    return;

  if (!MxOmni::GetInstance())
    return;

  if (!AtomIdTree())
    return;

  TreeValue value = TreeValue(m_internal);
  TreeValue *p = &value;

  // 100ad052
  // should inline Search but NOT TreeValueCompare
  TreeNode *node = AtomIdTree()->Find(p);

  node->m_value->RefCountDec();
}

// OFFSET: LEGO1 0x100ad1c0
MxAtomId &MxAtomId::operator=(const MxAtomId &atomId)
{
  if (m_internal)
    Destroy();

  if (atomId.m_internal && MxOmni::GetInstance() && AtomIdTree()) {
    TreeValue *value = try_to_open(atomId.m_internal, LookupMode_Exact);
    value->RefCountInc();
  }

  m_internal = atomId.m_internal;

  return *this;
}

// OFFSET: LEGO1 0x100ad210
TreeValue *MxAtomId::try_to_open(const char *p_str, LookupMode p_mode)
{
  TreeValue *value = new TreeValue(p_str);

  switch (p_mode) {
    case LookupMode_LowerCase:
    case LookupMode_LowerCase2:
      value->m_str.ToLowerCase();
      break;
    case LookupMode_UpperCase:
      value->m_str.ToUpperCase();
      break;
  }

  // LAB_100ad2a1
  TreeNode *node = AtomIdTree()->Find(value);
  
  MxBinaryTree *tree = AtomIdTree();
  if (node->m_child0 != tree->m_root) {
    // unnecessary check?
    if (value)
      delete value;
    value = node->m_value;
  } else {
    // repeat?
    node = tree->Search(value);
    TreeNode *pOutput;

    // TODO: this is all wrong, but I wanted to see if
    // just slapping an approximation of the code down would reveal
    // the answer.
    if (AtomIdTree()->m_p2) {
      tree->Insert(&pOutput, pOutput, node, value);  
    } else {
      tree->Insert(&pOutput, pOutput, AtomIdTree()->m_root, value);  
    }
    
    // LAB_100ad42b
  }

  return value;
}

// OFFSET: LEGO1 0x100ad7e0
void MxAtomId::Clear()
{
  Destroy();
  m_internal = NULL;
}
