#include "list.h"
#include <stdlib.h>
#include <sys/types.h>  
//创建链表
MyList * createMyList()
{
	MyList *list = (MyList *) malloc(sizeof(MyList));
	if (!list)  
	{
		//		printf("申请内存失败\n");
		return NULL;
	}
	list->length = 0;
	list->first = NULL;
	list->last = NULL;
	return list;
}

//释放链表
void freeMyList(MyList* list,void(*freeData)(void *))
{
	MyNode *p = NULL;
	while (list->first)
	{
		p = list->first->next;
		(*freeData)(list->first->data);
		free(list->first);
		list->first = p;
	}	
	free(list);
}

//链表的反向
void myListReverse(MyList *list)
{
	if (list == NULL && list->first == NULL)  return ;
	MyNode *p = list->last;
	MyNode *temp = p->next;
	list->last = list->first;
	list->first = p;
	while (p)
	{
		temp = p->next;
		p->next = p->prior;
		p->prior = temp;
		p = p->next;	
	}
}


//插入在尾部
void myListInsertDataAtLast(MyList* const list, void* const data)
{
	//printf("插入尾部\n");
	MyNode *node = (MyNode *) malloc(sizeof(MyNode));
	if (!node) 
	{
		printf("申请内存失败\n");
		return;
	}
	node->data = data;
	node->next = NULL;
	//printf("data复制成功\n");
	//printf("list->length=%d\n", list->length);
	if (list->length)
	{
		//printf("插入不是第一个节点\n");
		list->last->next = node;
		node->prior=list->last;
		list->last = node;
	} 
	else
	{
		//printf("插入为第一个节点\n");
		node->prior = NULL;
		list->first = node;
		list->last = node;
	}
	(list->length)++;
}

//插入在首部
void myListInsertDataAtFirst(MyList* const list, void* const data)
{
	MyNode *node = (MyNode *) malloc(sizeof(MyNode));
	if (!node) 
	{
		//	printf("申请内存失败\n");
		return;
	}
	node->data = data;
	node->prior = NULL;
	if (list->length)
	{
		node->next = list->first;
		list->first->prior = node;
		list->first = node;
	}
	else
	{
		node->next = NULL;
		list->first = node;
		list->last = node;
	}
	(list->length)++;
}

//长度
int myListGetSize(const MyList* const list)
{
	return list->length;
}

//打印
void myListOutput(const MyList* const list, void(*pt)(const void* const))
{
	MyNode *p = list->first;
	while (p)
	{
		(*pt)(p->data);
		p = p->next;
	}
}


//反向打印
void myListOutput_reverse(const MyList* const list,void(*pt)(const void* const) )
{
	MyNode *p = list->last;
	while(p)
	{
		(*pt)(p->data);
		p = p->prior;
	}
	puts("");
}

//删除在尾部
void myListRemoveDataAtLast(MyList* const list)
{
	if (list->length == 0)  
	{
		return;
	}
	if (list->length == 1)
	{
		free(list->first);
		(list->length)--;
		list->first = NULL;
		list->last = NULL;
		return;
	}
	MyNode *p = list->last;
	//void *value = p->data;
	list->last = p->prior;
	list->last->next = NULL;
	free(p);
	(list->length)--;
	//return value;
}

//删除在首部
void myListRemoveDataAtFirst(MyList* const list)
{
	if (list->length == 0)  
	{
		//   printf("链表为NULL\n");
		return;
	}
	MyNode *p = list->first;
	list->first = p->next;
	list->first->prior = NULL;
	//void * value = p->data;
	free(p);
	(list->length)--;
	if (list->length == 0)
	{
		list->last = NULL;
	}
	//return value;
}



//插入
int myListInsertDataAt(MyList* const list, void* const data, int index)
{
	if (index  < 0 || index > list->length) 
	{
		//   printf("插入范围错误\n");
		return 0;
	}
	if (index == 0)
	{
		myListInsertDataAtFirst(list, data);
		return 1;
	}
	if (index == list->length)
	{
		myListInsertDataAtLast(list, data);
		return 1;
	}
	MyNode *node = (MyNode *) malloc(sizeof(MyNode));
	if (node == NULL)  
	{
		printf("申请内存失败\n");
		return 0;
	}
	node->data = data;
	MyNode *p = NULL;
	int mid = list->length/2;
	if (index < mid)
	{
		p = list->first;
		for (int i = 1; i < index; i++)
		{
			p = p->next;
		}
	}
	else 
	{
		p = list->last;
		for (int i = list->length; i > index; i--)
		{
			p=p->prior;
		}
	}
	node->next = p->next;
	p->next->prior = node;
	p->next = node;
	node->prior = p;
	(list->length)++;
	return 1;
}

//删除
/*
   void* myListRemoveDataAt(MyList* const list, int index)
   {
   if (index  < 0 || index >= list->length) 
   {
//   printf("删除范围错误\n");
return NULL;
}
if (index == 0)
{
return myListRemoveDataAtFirst(list);
}
if (index == list->length - 1)
{
return myListRemoveDataAtLast(list);
}
int mid = list->length/2;
MyNode *p = NULL;
MyNode *temp = NULL;
if (index < mid)
{
p = list->first;
for (int i=1; i < index; i++)
{ 
p=p->next;
}

}
else 
{
p = list->last;
for( int i = list->length; i > index; i--)
{   
p=p->prior;
}
}
temp = p->next;
void *value = temp->data;
p->next = temp->next;
temp->next->prior = p;
free(temp);
(list->length)--;
return value;
}
 */

//取得数据
void* myListGetDataAt(const MyList* const list, int index)
{
	if (index  < 0 || index > list->length - 1 ) 
	{
		printf("查找范围错误\n");
		return NULL;
	}
	int mid = list->length/2;
	MyNode *p = NULL ;
	if (index < mid )
	{
		p = list->first;
		for(int i=1; i <= index; i++)
		{ 
			p = p->next;	
		}
	}
	else 
	{
		p = list->last;
		for(int i = list->length; i > index + 1; i--)
		{
			p = p->prior;
		}
	}
	return p->data;   


}

//取得第一个数据
void* myListGetDataAtFirst(const MyList* const list)
{
	return list->first->data;
}

//取得最后一个数据
void* myListGetDataAtLast(const MyList* const list)
{
	return list->last->data;
}

//按照某种条件查找第一个节点
MyNode*  myListFindDataNode(const MyList* const list ,const void* const data,int(*pt)(const void* const,const void* const))
{
	MyNode *p = list ->first;
	while(p)
	{
		if ((*pt)(p->data,data)) 
		{
			return p;
		}
		p = p->next;
	}
	return NULL;
}

//按照某种条件查找第一个节点
int  myListFindDataNodeindex( MyList *list ,int(*pt)( void*))
{
	MyNode *p = list ->first;
	int index = 0;
	while(p)
	{
		if ((*pt)(p->data)==1) 
		{
			return index;
		}
		index++;
		p = p->next;
	}
	return -1;
}


//按照某种条件查找所有节点
MyList*  myListFindDataAllNode( MyList*  list ,int(*pt)( void*), void (*freedata)(void *))
{
	MyNode *p = list ->first;
	MyList *newList = NULL;
	newList = createMyList();
	while(p)
	{
		if ((*pt)(p->data)) 
		{
			//	temp = (MyNode *) malloc(sizeof(MyNode));
			//	if (temp != NULL)
			//	temp->data = p->data;
			//	else return NULL;
			myListInsertDataAtLast(newList, p->data);
		}
		else 
		{
			(*freedata)(p->data);
		}
		p = p->next;
	}
	p = NULL;
	while (list->first)
	{
		p = list->first->next;
		free(list->first);
		list->first = p;
	}	
	free(list);

	return newList;
}

//快速排序  内部不给用户
void myListQuicksort(MyNode* first, MyNode* last,int(*pt)( void*  , void* ))
{
	if (first == last || !first || !last)  
	{
		return ;
	}
	MyNode *low = first;
	MyNode *high = last;
	void *  p=first->data;
	while(first != last)
	{
		while (first != last && (*pt)(p,last->data)) 
		{
			last = last->prior;
		}
		if (first != last)
		{
			first->data = last->data;
			first = first->next; 
		}
		else break;
		while (first != last && (*pt)(first->data,p))
		{
			first = first->next;
		}
		if (first != last)
		{
			last->data = first->data;
			last = last->prior;
		}
		else break;
	}
	last->data = p;

	if (low != first)
	{
		myListQuicksort(low,first->prior,(*pt));
	}
	if (first!=high)  
	{
		myListQuicksort(first->next,high,(*pt));
	}
}


void  myListQuickSort(MyList * const list ,int(*cmp)( void *  , void * ))
{
	MyNode *first = list->first;
	MyNode *last = list->last;
	myListQuicksort(first, last, (*cmp));
}


//插入排序
void myListInsertSort(MyList *const list, int (*cmp)( void * ,  void * ))
{
	if(list == NULL)	return ;
	MyNode *p = list->first;
	MyNode *now = p->next;
	MyNode *nownext = NULL;
	while (now)
	{	nownext = now->next;
		for(p = list->first;(*cmp)(p->data, now->data) && p && p != now; p = p->next );
		if (p != list->first && p !=now )  
		{
			if(nownext == NULL) 
			{
				now->prior->next = NULL;
				list->last = now->prior;
			}
			else	
			{
				now->prior->next = now->next;
				now->next->prior = now->prior;
			}
			now->next = p;
			now->prior = p->prior;
			p->prior->next = now;
			p->prior = now;
		}
		else if(p == list->first)
		{		
			if(nownext == NULL) 
			{
				now->prior->next = NULL;
				list->last = now->prior;
			}
			else	
			{
				now->prior->next = now->next;
				now->next->prior = now->prior;
			}
			p->prior = now;
			now->next = p;
			now->prior = NULL;
			list->first = now ;
		}

		now = nownext;
	}
}

//查找id src_ip dst_ip相同的节点
MyNode* find_info(MyList *list, u_char id1, u_char id2, int srt_ip, int dst_ip, int (*cmp_id_ip)(void *, u_char, u_char, int, int))
{
	MyNode *p1 = list->first;
	do
	{
		//printf("ssss\n");
		if((*cmp_id_ip)(p1->data, id1, id2, srt_ip, dst_ip) == 1)
		{
			return p1;	
		}
		else
		{
			p1=p1->next;
		}
	}
	while(p1 != NULL);
	return p1;
}


//按照偏移量顺序插入排序
void insert_sort(MyList *list, void *data, int (*cmp_offset)(void *, void *), void (*free_data_2)(void *))
{
	//printf("插入前\n");
	if(list->length == 0)
	{
		myListInsertDataAtLast(list, data);
		return;
	}	
	else if(list->length == 1)
	{
		//printf("第二个节点插入前\n");
		if((*cmp_offset)(data, list->first->data) == 2)
		{
			//printf("第二个节点偏移量大于第一个\n");
			myListInsertDataAtLast(list, data); 
			return;
		}	
		else if((*cmp_offset)(data, list->first->data) == 1)
		{
			myListInsertDataAtFirst(list, data);
			return;
		}

		else
		{
			(*free_data_2)(data);
			return;
		}					
	}
	else
	{
		//printf("第三个节点插入前\n");
		MyNode *p1 = list->first;
		MyNode *p2 = list->first->next;
		while(p2)
		{
			if((*cmp_offset)(data, p1->data) == 1)//小于p1
			{
				if(p1 == list->first)//p1是头
				{
					myListInsertDataAtFirst(list, data);
					return;
				}	
				else//p1不是头
				{
					MyNode *node = (MyNode *) malloc(sizeof(MyNode));
					if (node == NULL) 
					{
						perror("malloc node");
						return;
					}
					node->data = data;
					node->next = p1;
					node->prior = p1->prior;
					p1->prior->next = node;
					p1->prior = node;
					(list->length)++;
					return;
				}
			}				
			else if((*cmp_offset)(data, p2->data) == 2)	//大于p2
			{
				//printf("第3个节点偏移量大于第2个\n");
				if(p2 == list->last)//p2是尾节点
				{
					myListInsertDataAtLast(list, data);
					return;
				}
				else if((*cmp_offset)(data, p2->next->data) == 1)
				{
					MyNode *node = (MyNode *) malloc(sizeof(MyNode));
					if (node == NULL) 
					{
						perror("malloc node");
						return;
					}
					node->data = data;
					printf("第3个节点数据赋值成功\n");
					node->next = p2->next;

					node->next->prior = node;
					node->prior = p2;
					p2->next = node;
					(list->length)++;
					return;
				}
				else
				{
					p1 = p1->next;
					p2 = p2->next;
				}
			}
			else if((*cmp_offset)(data, p1->data) == 2 && (*cmp_offset)(data, p2->data) == 1)//p1,p2之间
			{
				MyNode *node = (MyNode *) malloc(sizeof(MyNode));
				if (node == NULL) 
				{
					perror("malloc node");
					return;
				}
				node->data = data;
				node->next = p2;
				p2->prior = node;
				node->prior = p1;
				p1->next = node;
				(list->length)++;
				return ;
			}
			else//等于p1或者p2
			{
				(*free_data_2)(data);
				return;
			}

		}
	}	
}
/*
   void delete_node(MyList *list, MyNode *p, void (*free_data_1)(void *))
   {

   if(list->length == 0)
   {
   return;
   }	
   else if(list->length == 1)
   {


   myListRemoveDataAtLast(list);
   return;
   }
   else
   {

   MyNode *p1 = list->first;
   while(p1)
   {
   if(p == p1)
   {
   if(p1 == list->first)
   {
   myListRemoveDataAtFirst(list);
   return;
   }
   else if(p1 == list->last)
   {
   myListRemoveDataAtLast(list);
   return;
   }
   else
   {
   p1->prior->next = p1->next;
   p1->next->prior = p1->prior;
   (*free_data_1)(p1->data);
   free(p1);
   p1 = NULL;
   (list->length)--;
   }
   }
   else
   {
   p1 = p1->next;
   }
   }
   }
   }
 */


void delete_node(MyList *list, MyNode *p, void (*free_data_1)(void *))
{

	if(list->length == 0)
	{
		return;
	} 
	else if(list->length == 1)
	{
		(*free_data_1)(list->first->data);
		free(list->first);
		list->first = NULL;
		list->last = NULL;
		(list->length)--;
		return;
	}
	else
	{
		MyNode *p1 = list->first;
		while(p1)
		{
			if(p == p1)
			{
				if(p1 == list->first)
				{
					list->first = p1->next;
					list->first->prior = NULL;
					(*free_data_1)(p1->data);
					free(p1);
					(list->length)--;
					return;
				}
				else if(p1 == list->last)
				{
					list->last = p1->prior;
					p1->prior->next = NULL;
					(*free_data_1)(p1->data);
					free(p1);
					(list->length)--;
					return;
				}
				else
				{
					p1->prior->next = p1->next;
					p1->next->prior = p1->prior;
					(*free_data_1)(p1->data);
					free(p1);
					p1 = NULL;
					(list->length)--;
					return;
				}
			}
			else
			{
				p1 = p1->next;
			}
		}
	}
}
