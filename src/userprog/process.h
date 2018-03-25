#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

//----------------
#include <list.h>
//----------------

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

//==============================
//Test stack function 
// Brian gave us his testing script, don't need this at the moment.
//void test_stack(int *t);
//==============================
//working on input argument ot start_process()
//setting so that it is now a struct pass_in *
//      instead of char *
//----------------------------------
struct pass_in //----------------------------------
{//----------------------------------
    bool load_success;//----------------------------------
    char *file_name;//----------------------------------
    //void *shared;//----------------------------------
    //changing from char* to struct*//----------------------------------
    //struct shared_data *shared;//----------------------------------
    struct thread *parent;
    struct shared_data **shared;
};//----------------------------------

#endif /* userprog/process.h */
