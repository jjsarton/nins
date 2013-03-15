/* file update_hosts.c
 * Insert/delete entry from ninsd int the file
 * /etc/host ort the given host file
 * Added IPv4 handling on march 2013 11
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include "list.h"

#define HOSTS "/etc/hosts"
#define PRESERVE 0
#define DELETE   1
#define UPDATE   2

#define LINE_SIZE 1024

typedef struct {
    int  status;
    char line[LINE_SIZE];
} hosts_line_t;

list_t *root = NULL;

static int cmp_name(const list_t *elem, const void *key)
{
    hosts_line_t *entry = (hosts_line_t *)elem->data;
    char *k = (char *)key;
    char *e = entry->line;
    int   ret = 0;

    /* skip comments and ip entry */

    while(*e && isspace(*e) )
        e++;

    if ( *e == '#' || *e == '\0' )
        return 1;

    while (*e && !isspace(*e))
        e++;

    while(*e && isspace(*e) )
        e++;

    while( *k && !(ret =*k-*e) )
    {
        e++;
        k++;
    }
    if ( ! ret && *e )
        ret = 1;

    return ret;
}

static void copy_line(char *dest, char *source)
{
    char *d = dest;
    char *s = source;
    while(*source)
    {
       if ( *source == '\n' || *source == '\r' )
           break;
       *dest++ = *source++;
    }
    *dest = '\0';
}

static int read_hosts(char *hosts)
{
    hosts_line_t *line;
    char buf[LINE_SIZE];
    FILE *fp;
    if ( ( fp = fopen(hosts,"r") ) )
    {
       while ( fgets(buf,sizeof(buf), fp) )
       {
           if ( (line = calloc(1, sizeof(hosts_line_t))) )
           {
               line->status = PRESERVE;
               copy_line(line->line, buf);
               if ( !list_append(&root,line) )
               {
                   fclose(fp);
                   exit(1);
               }
           }
           else
           {
               syslog("calloc");
               fclose(fp);
               exit(1);
           }
       }
       fclose(fp);
    }
}

static read_command()
{
    char buf[LINE_SIZE];
    char name[LINE_SIZE];
    char IP[LINE_SIZE];
    char dummy[LINE_SIZE];
    char type[LINE_SIZE];
    list_t *elem;
    hosts_line_t *entry;
    int found6 = 0;
    int found4 = 0;
    while ( fgets(buf,sizeof(buf), stdin) )
    {
       int e = strlen(buf);
       e--;
       if ( e > -1 ) buf[e]='\0';
       if ( strstr(buf, "update delete") )
       {
          /* 3. arg is the node and 4. the entry type */
          sscanf(buf, "%s %s %s %s", dummy, dummy, name, type);
          elem = root;
          while ( (elem = list_search(elem, name, cmp_name)) )
          {
             entry = (hosts_line_t *)elem->data;
             if ( strchr(entry->line, ':') && strcmp(type,"AAAA") == 0 )
             {
                 /* an IPv6 entry */
                 entry->status = DELETE;
             }
             else if ( !strchr(entry->line, ':') && strcmp(type,"A") )
             {
                 /* an IPv4 entry */
                 entry->status = DELETE;
             }
             elem = elem->next;
          }
       }
       else if ( strstr(buf, "update add") )
       {
          /* 3. name 5. ttl 6, type, 7. IP */
          sscanf(buf, "%s %s %s %s %s %s", dummy, dummy, name, dummy, dummy, IP);
          elem = root;
          while ( (elem = list_search(elem,name, cmp_name)) )
          {
             entry = (hosts_line_t *)elem->data;
             if ( strchr(entry->line, ':') && strchr(IP,':') )
             {
                 /* an IPv6 entry */
                 if ( entry->status == DELETE )
                 {
                     entry->status = UPDATE;
                     char *p, *q;
                     if ( (p = strstr(entry->line, IP)) )
                     {
                         if ( p == entry->line )
                         {
                             q = p + strlen(IP);
                             if ( isspace(*q) )
                                 entry->status = PRESERVE;
                         }
                     }
                 }
                 /* replace the IP addr may be changed */
                 snprintf(entry->line,LINE_SIZE,"%s %s",IP,name);
                 found6 = 1;
             }
             else if ( strchr(entry->line, ':') == NULL &&  strchr(IP,':') == NULL)
             {
                 /* an IPv6 entry */
                 if ( entry->status == DELETE )
                 {
                     entry->status = UPDATE;
                     char *p, *q;
                     if ( (p = strstr(entry->line, IP)) )
                     {
                         if ( p == entry->line )
                         {
                             q = p + strlen(IP);
                             if ( isspace(*q) )
                                 entry->status = PRESERVE;
                         }
                     }
                 }
                 /* replace the IP addr may be changed */
                 snprintf(entry->line,LINE_SIZE,"%s %s",IP,name);
                 found4 = 1;
             }
             elem = elem->next;
          }

          if ( (!found6 && strstr(IP,":")) || (!found4 && !strstr(IP,":")) )
          {
             /* unknown; add element */
             if ( (entry = calloc(1, sizeof(hosts_line_t))) )
             {
                 entry->status = UPDATE;
                 snprintf(entry->line,LINE_SIZE,"%s %s",IP,name);
                 if ( !list_append(&root,entry) )
                    exit(1);
             }
             else
             {
                 perror("calloc");
                 exit(1);
             }
          }
       }
    }
}

static void free_list(void)
{
    list_t *elem = root;
    while(elem)
    {
       free(root->data);
       list_remove(&root,elem);
       elem = root;
    }
}

static writeout(FILE *out)
{
    list_t *elem = root;
    hosts_line_t *entry;
    while (elem)
    {
        entry = (hosts_line_t*)elem->data;
        if ( entry->status != DELETE )
        {
           fprintf(out,"%s\n",entry->line);
        }
        elem = elem->next;
    }
}

static check_for_update(void)
{
    list_t *elem = root;
    hosts_line_t *hl;
    while ( elem )
    {
        hl = (hosts_line_t *)elem->data;
        if ( hl->status != PRESERVE )
        {
            return 1;
        }
        elem = elem->next;
    }
    return 0;
}

static void usage(char *me)
{
    printf("Syntax: %s [-f hosts_file]\n",me);
    printf("\t%s update the file /etc/hosts according to the\n",me);
    printf("\tdatas passed by the ninsd/nins_update.sh\n");
    printf("\tThe -f hosts_file allow to perform tests without\n");
    printf("\tmodification of the real hosts file.\n");
}

int main(int argc, char **argv)
{
    char *hosts = NULL;
    FILE *fp;
    int c;
    char *me;
    if ( (me = strchr(argv[0],'/')) )
       me++;
    else
        me = argv[0];

    while((c = getopt(argc, argv, "f:")) > 0 )
    {
        switch(c)
        {
            case 'f':
                hosts=strdup(optarg);
            break;
            default:
                usage(me);
                exit(0);
        }
    }

    if ( hosts == NULL )
        hosts=strdup(HOSTS);

    read_hosts(hosts);
    read_command();
    c = check_for_update();
    if ( c && (fp=fopen(hosts,"w")) )
    {
        writeout(fp);
        fclose(fp);
    }
    free_list();
    if ( hosts )
        free(hosts);

    return 0;
}
