#include <stdlib.h>
#include "list.h"

/**************************************************************
 *
 * Function: list_insert()
 *
 * Insert before the element pointed by **list a new list
 * element.
 * If *älist is null a new root element is created.
 *
 * The data are not duplicated.
 *
 * Parameters:
 *   list_t **list   pointer to a list element
 *   void    *data   data to attach to the list
 *
 * Return: 1 on success 0 on error
 *
 * Example:
 *   list_t *root;
 *   char   *data = "1";
 *   list_insert(&root, (const void*)data;
 *
 *************************************************************/

int list_insert(list_t **list, void *data)
{
   list_t *prev = NULL;
   list_t *next = NULL;
   list_t *new;

   if ( list == NULL )
   {
      return 0;
   }
   
   new = (list_t*)calloc(sizeof(list_t),1);
   new->data = data;

   if ( new )
   {
      if ( *list == NULL )
      {
         /* top element */
         *list = new;
      }
      else
      {
         prev = (*list)->prev;
         next = (*list)->next;
         if ( prev )
         {
            /* insert at end or between 2 elements */
            /* eg list is c new is b  a - c -> a - b - c */
            new->prev = prev;
            new->next = *list;

            prev->next = new;

            if ( next )
            {
               next->prev = new;
            }
         }
         else
         {
            /* list point to the top element */
            /* b - c  -> a - b - c */
            (*list)->prev = new;
            new->next = *list;
            *list = new;
         }
      }
      return 1;
   }

   return 0;
}

/**************************************************************
 *
 * Function: list_append()
 *
 * Attach at the list end the element pointed by **list a new list
 * element.
 * If *älist is null a new root element is created.
 *
 * The data are not duplicated.
 *
 * Parameters:
 *   list_t **list   pointer to a list element
 *   void    *data   data to attach to the list
 *
 * Return: 1 on success 0 on error
 *
 * Example:
 *   list_t *root;
 *   char   *data = "1";
 *   list_append(&root, (const void*)data;
 *
 *************************************************************/

int list_append(list_t **list, void *data)
{
   list_t *prev;
   list_t *next;
   list_t *new;
   
   if ( list == NULL )
   {
      return 0;
   }
   
   new = (list_t*)calloc(sizeof(list_t),1);
   new->data = data;
   /* not element are within the list */
   if ( *list == NULL )
   {
      (*list) = new;
      return 1;
   }

   prev = *list;
   next = (*list)->next;
   while(next)
   {
      prev = next;
      next = next->next;
   }
   prev->next = new;
   new->prev = prev;

   return 1;
}

/**************************************************************
 *
 * Function: list_remove()
 *
 * Delete the element pointed by *list.
 * The datas attached to the *data variable must be freed
 * before removing the element.
 *
 * Parameters:
 *   list_t **root   pointer to the root element
 *   list_t  *list   pointer to a list element
 *
 * Return: 1 on success 0 on error
 *
 * Example:
 *   list_t **root;
 *   list_t  *elem;
 *   char   *data[2] = { "1", "2" };
 *   list_append(&root, (const void*)data);
 *   list_append(&root, (const void*)data);
 *   elem = NULL;
 *   elem = list_search(&root,&item);
 *   list_remove(&root, elem)
 *
 *   // Remove all elements
 *   while(root)
 *   {
 *      freeData(root->data);
 *      list_remove(&root,root);
 *   }
 *
 *************************************************************/

int list_remove(list_t **root, list_t *list)
{
   list_t *prev;
   list_t *next;

   if ( list == NULL || root == NULL )
   {
      return 0;
   }

   prev = (list)->prev;
   next = (list)->next;
   
   if ( prev )
   {
      prev->next = next;
      if ( next )
      {
         next->prev = prev;
      }
      free(list);
      list = prev;
   }
   else
   {
      /* top element */
      if ( next )
      {
         next->prev = NULL;
      }
      free(list);
      *root = next;
      list = next;
   }
   return 1;
}

/**************************************************************
 *
 * Function: list_iterate()
 *
 * Walk from the root element up to the last element of the list
 *
 * The parameter list must be initianlized to NULL for the firstcall
 *
 * The list paramenter point to the next element.
 *
 * Parameters:
 *   list_t  *root   pointer to the root element
 *   list_t **list   pointer to a list element
 *
 * Return: *list pointer to the next element or NULL
 *
 * Example;
 *   list_t *root;
 *   ...
 *   list_t *item = NULL;
 *   while ((item=list_iterate(&root,&item)) != NULL)
 *     ;
 *
 *************************************************************/

list_t * list_iterate(list_t *root, list_t **list)
{
    if ( list == NULL )
    {
       return NULL;
    }

    if ( *list != NULL )
    {
       *list = (*list)->next;
    }
    else if ( root != NULL )
    {
       *list = root;
    }
    else
    {
       return NULL;
    }

    return *list;
}

/**************************************************************
 *
 * Function: list_search()
 *
 * Search an list element.
 *
 * The parameter list must be initianlized to NULL for the firstcall
 *
 * The list paramenter point to the next element.
 *
 * Parameters:
 *   list_t  *list   pointer to the root element
 *   void *key       data to be searched
 *   compar          function returning a negati positive or zero
 *                   according to the data to be comrared
 *
 * Return: *list pointer to searched element or NULL
 *
 * Example;
 *   int compare(list_t *list, void *key)
 *   {
 *      return strcmp((char*)list->data, (char *)key));
 *   }
 *
 *   list_t *root;
 *   ...
 *   list_t *item = list_search(root, "1", compare);
 *   
 *************************************************************/

list_t *list_search(list_t *list, const void *key,  int (*compar)(const list_t *, const void *))
{
   list_t *root = list;

   if ( root == NULL || key == NULL )
   {
      return NULL;
   }
   
   while(list)
   {
      if ( compar(list,key) == 0 )
      {
         return list;
      }
      else
      {
         list = list->next;
      }
   }
   return NULL;
}

