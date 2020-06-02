#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

//#include <uprotected_fs.h>

#include <time.h>

//#ifndef KEY_VALUE_API
//#define KEY_VALUE_API

#include<linux/unistd.h>
#include<linux/kernel.h>
#include<sys/syscall.h>
#include<stdlib.h>
//#include<dumpcode.h>


int cntw=0;
double timewr=0;


//fd는 0으로
//이건 ocall이라 packing만 해주는 함수라고 생각해야함
//fileID는 write할때 필요한거라 여기에선 필요가 없음
int spm_send_cmd(int fd, char* buffer, int node_size, char* response, int pid, spm_param*sp)
{
    uint64_t offset = 0;
    uint32_t ret_msg;
    uint32_t file_size = node_size;
    uint32_t reserved;
    DS_PARAM *ds_param = (DS_PARAM*) malloc (sizeof(DS_PARAM));
    char *u_buf_ = (char*) malloc (sizeof(char)*(IO_SIZE + SECTOR_SIZE));    //IO_SIZE??
    char *u_buf = (char*) ((((unsigned long)u_buf_ + SECTOR_SIZE -1 ) >> SECTOR_BIT) << SECTOR_BIT);
    
    int cmd = ds_param->cmd = sp->cmd;
    ds_param->fd = fd;
    ds_param->offset = offset;
    
    //ds_param->size = (((node_size + 8)+SECTOR_SIZE-1) >> SECTOR_BIT) << SECTOR_BIT;
    
    memcpy((char*)u_buf, buffer, file_size);
    
    if((reserved=file_size%512)!= 0)    //섹터단위로 안나뉘면 dummy값넣어줘야
    {
        fprintf(stdout, "never be called!!!\n");
        memset((char*)(u_buf+file_size), 0x00, 512-reserved);
        file_size += (512-reserved);
    }
    
    //cmd는 register fis로 보낼거
    
    unsigned char key[160] = { 0x00, };
    unsigned char in[200] = { 0x00, };
    unsigned char mac[160] = { 0x00, };
    int keyLen = 0, inLen = 0, macLen = 0;

    unsigned char after_enc[100] = {0, };
    switch (cmd) {
        case SPM_CREATE:
            //memcpy((char*)(u_buf+file_size), (char*)(&sp->pid), 4);
            memcpy((char*)(u_buf+file_size), (char*)(&pid), 4);
            memcpy((char*)(u_buf+file_size+4), (char*)(&sp->ret_time), 4);
            memcpy((char*)(u_buf+file_size+8), (char*)(&sp->backup_cycle), 4);
            memcpy((char*)(u_buf+file_size+12), (char*)(&sp->version_num), 4);
            //여기위에서 뻑남
            /*
            memcpy((char*)(u_buf+file_size+16), (char*)(&mac), 32);
            ds_param->size = (((node_size + 48)+SECTOR_SIZE-1) >> SECTOR_BIT) << SECTOR_BIT;
            */
            
            /*
            SHA256_Encrpyt((unsigned char*)u_buf, 12, after_enc);
            
            keyLen = asc2hex(key, "CAEE9E66F060D74BDA1C7636F765FFB5");
            inLen = asc2hex(in, "123456789012"); //12바이트
            macLen = 8;
            print_result("SEED Generate_CMAC", SEED_Generate_CMAC(mac, macLen, in, inLen, key));
            */
            //memcpy((char*)(u_buf+file_size+16), (char*)(&mac), 4);
            ds_param->size = (((node_size + 16)+SECTOR_SIZE-1) >> SECTOR_BIT) << SECTOR_BIT;
            break;
        case SPM_CHANGE:
            //pid의 정책이 파라미터들로 바뀜
            //memcpy((char*)(u_buf+file_size), (char*)(&sp->pid), 4);
            memcpy((char*)(u_buf+file_size), (char*)(&pid), 4);
            memcpy((char*)(u_buf+file_size+4), (char*)(&sp->ret_time), 4);
            memcpy((char*)(u_buf+file_size+8), (char*)(&sp->backup_cycle), 4);
            
            /*
            memcpy((char*)(u_buf+file_size+16), (char*)(&mac), 32);
            ds_param->size = (((node_size + 48)+SECTOR_SIZE-1) >> SECTOR_BIT) << SECTOR_BIT;
            */
            
            /*
            SHA256_Encrpyt((unsigned char*)u_buf, 12, after_enc);
            
            keyLen = asc2hex(key, "CAEE9E66F060D74BDA1C7636F765FFB5");
            inLen = asc2hex(in, "123456789012"); //12바이트
            macLen = 8;
            print_result("SEED Generate_CMAC", SEED_Generate_CMAC(mac, macLen, in, inLen, key));
            
            //memcpy((char*)(u_buf+file_size+16), (char*)(&mac), 4);
             */
            ds_param->size = (((node_size + 16)+SECTOR_SIZE-1) >> SECTOR_BIT) << SECTOR_BIT;
            break;
        default:
            printf("[APP] Invalid SPM command\n");
            return -1;
            break;
    }
    
    enc_rdafwr(ds_param, u_buf, response, ds_param->size);
    free(u_buf_);
    free(ds_param);
    return 0;
}


void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

void printf_helloworld()
{
    printf("Hello World\n");
}

