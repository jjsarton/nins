/* ninsd_param.h
 * parameters for fonctions call
 *
 */
 
typedef struct {
    int   local;
    char *updater;
    char *device;
    int   ttl;
} config_t;

typedef struct {
    config_t config;
    int      sock;
    struct   in6_addr own_addr;
    struct   sockaddr_in6 whereto;
    int      ttl;
    char     outpack[4096];
    char     domain[NAME_SIZE_MAX];
} param_t;
