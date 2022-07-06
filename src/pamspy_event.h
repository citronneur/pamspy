#ifndef __EVENT_H__
#define __EVENT_H__

/*!
 *  \brief  information tracked by pamspy
 */
typedef struct _event_t {
    int  pid;           // pid of the process
    char comm[16];      // name of the process
    char username[80];
    char password[80];  // secrets
} event_t;

#endif
