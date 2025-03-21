#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include<unistd.h>
#include<string.h>
#include<sys/shm.h>

#define EM_CALLTRACE_SHM_NOT_INIT 0
#define EM_CALLTRACE_SHM_ERROR -1
#define EM_INFO 0
#define EM_WARN 1
#define EM_ERROR 2


extern unsigned long aflnet_state;
extern unsigned long stateafl_state;
unsigned char* em_calltrace_shm=NULL;
int em_log_fd = 0;

void em_log(int type,char* msg){
    if(em_log_fd==0){
        exit(3);
    }
    char log_buf[100];
    memset(log_buf, 0x0 ,100);
    sprintf(log_buf,"[LOG] %s\n",msg);
    write(em_log_fd, log_buf, strlen(log_buf));
    if(type == EM_ERROR){
        exit(2);
    }
    return;
}

void init_log(){
    if(em_log_fd==0){
        em_log_fd = open("./em_log", O_RDWR);
        if(em_log_fd < 0){
            exit(3);
        }
    }
    return;
}

void close_log(){
    if(em_log_fd){
        close(em_log_fd);
    }
    return;
}

unsigned long fstate_extract(){
    if(em_calltrace_shm == EM_CALLTRACE_SHM_NOT_INIT || em_calltrace_shm == (void*)EM_CALLTRACE_SHM_ERROR){
        em_log(EM_ERROR,"shm not init");
    }
    char* fuzzer=getenv("EM_CALLTRACE_FUZZER");
    if(!strcmp(fuzzer, "aflnet"))
        return aflnet_state;
    if(!strcmp(fuzzer, "stateafl"))
        return stateafl_state;
    return 0;
}

int init_calltrace_shm(){
    char* shm_id=getenv("EM_CALLTRACE_SHM");
    if(shm_id){
        int id=atoi(shm_id);
        em_calltrace_shm = (unsigned char*)shmat(id, NULL, 0);
        em_log(EM_INFO, "SHM of calltrace setup");
        return 0;
    }else{
        em_log(EM_ERROR, "SHM of calltrace not setup");
    }
}

