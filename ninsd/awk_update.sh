#!/bin/sh

# update via gawk may be done as follow

HOSTS=/etc/hosts

awk -F' ' 'BEGIN {
    i = 0;
    # read the hosts file
    while ( getline < "'$HOSTS'" ) {
       line[i] = $0;
       ip[i]   = $1;
       name[i] = $2;
       mark[i] = "preserve";
       i++;
    }
    # assume no modifications
    mod = 0;
} {
    if ( $1 == "update" && $2 == "delete" )
    {
       for ( j = 0; j < i; j++ )
       {
          if ( name[j] == $3 )
          {
             mark[j] = "delete";
             mod++;
          }
       }
    }
    if ( $1 == "update" && $2 == "add" )
    {
       found = 0;
       # if we had previously a delete
       for ( j = 0; j < i; j++ )
       {
          if ( name[j] == $3 )
          {
             found = 1;
             if ( ip[j] == $6 )
             {
                 # same ip no changes
                 mark[j] = "preserve";
                 mod--;
             }
             else
             {
                 # ip change true nodification
                 ip[j] = $6;
                 line[j] = sprintf("%s %s",$6, name[j]);
                 mark[j] = "update";
             }
             break;
          }
       }
       if ( !found )
       {
           # this will be appended to the file
           name[i] = $3;
           line[i] = sprintf("%s %s",$6,$3);
           mark[i] = "add";
           i++;
           mod++;
       }
    }
} END {
    # write back the host file
    if ( mod > 0 )
    {
        printf("") > "'$HOSTS'"
        for ( j = 0; j < i; j++ )
        {
           if ( mark[j] != "delete" )
           {
               printf("%s\n", line[j]) >> "'$HOSTS'";
           }
        }
        system("pkill -SIGHUP dnamasq");
    }
}'
