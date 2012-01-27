#ifndef LIST_H
#define LIST_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

typedef struct list_s
{
   struct list_s *next;
   struct list_s *prev;
   char          *data;
} list_t;


extern int list_remove(list_t **root,list_t *list);
extern int list_insert(list_t **list, void *data);
extern int list_append(list_t **list, void *data);
extern list_t *list_search(list_t *list, const void *key,  int (*compar)(const list_t *, const void *));
extern list_t *list_iterate(list_t *root, list_t **list);

#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* LIST_H */
