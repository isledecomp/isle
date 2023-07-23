#ifndef MXBINARYTREE_H
#define MXBINARYTREE_H

#include "mxstring.h"

// TODO: enum instead?
#define NODE_COLOR_RED   0
#define NODE_COLOR_BLACK 1

// SIZE 0x14
class TreeValue {
public:
  TreeValue(const char *p_str)
  {
    m_str = p_str;
    m_t0 = 0;
  }

  void RefCountInc();
  void RefCountDec();

  MxString m_str;
  MxU16 m_t0;
  MxU16 m_t1;
};

// SIZE 0x14
class TreeNode {
public:
  TreeNode(TreeNode *p_parent, int p_color)
  {
    m_parent = p_parent;
    m_color = p_color;
  }

  TreeNode *m_child0; // +0 // string sorts after
  TreeNode *m_parent; // +4 // parent node
  TreeNode *m_child1; // +8 // string sorts before
  TreeValue *m_value; // +c
  int m_color; // +10 // BLACK or RED.
};

// SIZE 0x10
class MxBinaryTree
{
public:
  // Dummy node to represent null value.
  static TreeNode *g_Node_Nil;
  MxBinaryTree()
  {
    if (!g_Node_Nil) {
      g_Node_Nil = new TreeNode(NULL, NODE_COLOR_BLACK);
      g_Node_Nil->m_child0 = NULL;
      g_Node_Nil->m_child1 = NULL;
    }

    m_root = new TreeNode(g_Node_Nil, NODE_COLOR_RED);
  }

  void LeftRotate(TreeNode *);
  void RightRotate(TreeNode *);
  void FUN_100ad4d0(TreeNode **, TreeNode *, TreeNode *, TreeValue *&);
  TreeNode *Search(TreeValue *&);

  int m_p0; // +0
  TreeNode *m_root; // +4
  int m_p2; // +8
  int m_p3; // +c
};

#endif //MXBINARYTREE_H