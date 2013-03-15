#ifndef NSUPD_FROM_H
#define NSUPD_FROM_H

#if defined (__cplusplus) || defined (c_plusplus)
extern "C" {
#endif

extern int open_listener(int port);
extern int update_from(int listener, char *updater);

#if defined (__cplusplus) || defined (c_plusplus)
}
#endif

#endif /* NSUPD_FROM_H */
