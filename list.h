#ifndef LIST_H_INCLUDED
#define LIST_H_INCLUDED
#include <stdio.h>
#include <sys/types.h>  

typedef struct myNode
{
	void * data;
    struct myNode *prior;
	struct myNode *next;
} MyNode;

typedef struct myList
{
	MyNode * first;
	MyNode * last;
	int length;
} MyList;


//创建链表
MyList * createMyList();

//链表的反向
void myListReverse(MyList *list);

//释放链表
void freeMyList(MyList * list, void(*freeData)(void *));

//插入在尾部
void myListInsertDataAtLast(MyList* const list, void* const data);

//插入在首部
void myListInsertDataAtFirst(MyList * const list, void* const data);

//插入
int myListInsertDataAt(MyList * const list, void* const data, int index);

//删除在尾部
void myListRemoveDataAtLast(MyList* const list);

//删除在首部
void myListRemoveDataAtFirst(MyList * const list);

//删除
//void* myListRemoveDataAt(MyList* const list, int index);

//删除对象,返回是否删除成功
int myListRemoveDataObject(MyList* const list, void * data);

//长度
int myListGetSize(const MyList * const list);

//打印
void myListOutput(const MyList * const list, void(*pt)(const void * const));

//查询节点
MyNode* myListFindDataNode(const MyList * const list,const void * const ,int(*pt)(const void * const,const void * const));

//查询满足调件节点下标
int  myListFindDataNodeindex( MyList*  list ,int(*pt)( void*));

//查询所有节点
MyList* myListFindDataAllNode( MyList *  list ,int(*pt)( void * ), void (*freedata)(void *));

//反向打印
void myListOutput_reverse(const MyList * const list, void (*f)(const void * const));

//取得数据
void* myListGetDataAt(const MyList * const list, int index);

//取得第一个数据
void* myListGetDataAtFirst(const MyList * const list);

//取得最后一个数据
void* myListGetDataAtLast(const MyList * const list);

//快速排序
void  myListQuickSort(MyList * const list,int(*pt)( void *  , void * ));

void myListInsertSort(MyList *const list, int (*cmp)( void * ,  void * ));



//查找id src_ip dst_ip相同的节点
MyNode* find_info(MyList *list, u_char id1, u_char id2, int a, int b, int (*cmp_id)(void *, u_char, u_char, int, int));
//按照偏移量顺序插入排序
void insert_sort(MyList *list, void *data, int (*cmp_offset)(void *, void *), void (*free_data_2)(void *));
//按照节点指向的指针删除节点
void delete_node(MyList *list, MyNode *p, void (*free_data_1)(void *));
#endif // LIST_H_INCLUDED
