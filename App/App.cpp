#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <iostream>

const int BUF_MAX_SIZE = 1000;
const int para_MAX_SIZE = 3;
const int para_MAX_LEN = 100; //same as max directory size

#define SPM_CREATE 0x65
#define SPM_CHANGE 0x66
#define SPM_DELETE 0x67

#define POLICY_LIST "/home/jinu/Desktop/policy_list"

//8KB가 넘으면, 쪼개주는정도만..아닌가.....
//넘으면 mac다시계산해야할거같은데.
//얘를 호출할당시부터 8KB쪼개졌다가정 즉 u_buf사이즈 <=8KB
int enc_rdafwr(DS_PARAM *ds_param, char* u_buf, char* response, int count)
{
    //이걸 ocall로 하면 될듯
    uint32_t response_size=40;
    
    //direct I/O 할 버퍼에 저장.
    if(((uint64_t)u_buf & 0x01ff) != 0)    //sector단위라 마지막 9bit 가 0이어야함.
    {
        fprintf(stdout, "Error wrong I/O buffer address\n");
    }
    
    //char *response = (char*) c (sizeof(char)*RESPONSE_SIZE);
    int ret;
    printf("syscall!\n");
    ret = (int) syscall(__NR_enc_rdafwr, ds_param, u_buf, count);
    
    return ret;
}

void line_input(char in[BUF_MAX_SIZE]){
    char buf = 0;
    for(int i = 0; 1; i++){
        scanf("%c", &buf);
        in[i] = buf;
        if(buf == '\n'){
            in[i] = 0;
            break;
        }
        else if(i == BUF_MAX_SIZE && buf != '\n'){
            //buffer size error
            fprintf(stderr, "[error] MAX buffer size is %d\n", BUF_MAX_SIZE);
        }
    }
}

void parse_str(char in[BUF_MAX_SIZE], char out[para_MAX_SIZE][para_MAX_LEN]){
    char tmp[BUF_MAX_SIZE];
    int len = 0, para_size = 0, j = 0;
    //assume no space allows in first and last "in[]" components
    for(int i = 0; i < BUF_MAX_SIZE && in[i] != 0; i++){
        while(in[i] == ' ') i++;
        if(len != 0) tmp[len++] = ' ';
        while(in[i] != ' ' && in[i] != 0) {
            tmp[len++] = in[i];
            i++;
        }
    }
    
    for(int i = 0; i < len; i++){
        j = 0;
        while(tmp[i] != ' ' && i < len){
            out[para_size][j++] = tmp[i++];
        }
        out[para_size++][j] = 0;
    }
}

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];
    
    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }
    
    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }
    
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }
    
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

void ocall_print_string(const char *str)
{
    printf("%s", str);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    
    
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    
    printf_helloworld(global_eid);
    
    printf("**************************************************************\n");
    printf("* SGX-SSD policy manager                                     *\n");
    printf("*                                                            *\n");
    printf("* press command and parameter                                *\n");
    printf("*                                                            *\n");
    printf("* ex) {create|change|delete} {ret_time} {Backup_cycle}       *\n");
    printf("*                                                            *\n");
    printf("* units:                                                     *\n");
    printf("* retention time : day                                       *\n");
    printf("* Backup cycle   : day                                       *\n");
    printf("**************************************************************\n");
    
    //assume aurora input
    char in[1000];
    line_input(in);
    //debug
    //printf("%s\n", in);
    
    char para_arr[para_MAX_SIZE][para_MAX_LEN]; //save parameters
    parse_str(in, para_arr);
    
    //debug
    
    printf("parameter lists : \n");
    for(int i = 0; i < para_MAX_SIZE; i++){
        printf("%s\n", para_arr[i]);
    }
    
    char path[100];
    int command, retention_time, backup_cycle, version_number, pid;
    
    int branch = 0;
    
    if(para_arr[0][0] == 'c' && para_arr[0][1] == 'r'){
        command = SPM_CREATE;
    }
    else if(para_arr[0][0] == 'c' && para_arr[0][1] == 'h'){
        command = SPM_CHANGE;
    }
    else if(para_arr[0][0] == 'd' || para_arr[0][0] == 'D'){
        command = SPM_DELETE;
    }
    else if(para_arr[0][0] == 'r' || para_arr[0][0] == 'R'){
        //no recovery
        command = 3;
        branch = 1;
    }
    else{
        fprintf(stderr, "error : command\n");
        return 0;
    }
    
    if(command == SPM_CHANGE){
        //what pid to change?
        printf("what pid to change : ");
        scanf("%d", &pid);
    }
    
    strcpy(path, para_arr[1]);
    
    if(!branch){
        //not recovery
        retention_time = atoi(para_arr[1]);
        backup_cycle = atoi(para_arr[2]);
        //version_number = atoi(para_arr[4]);
    }
    else{
        //recovery
        //??
    }
    //debug
    //printf("data : %d%s%d%d%d\n", command, path, retention_time, backup_cycle, version_number);
    printf("data : %d%d%d\n", command, retention_time, backup_cycle);
    
    // FILE*fp = fopen("policy_list", "r+");
    
    
    //***********
    //must change
    //***********
    FILE*fp = fopen(POLICY_LIST, "r+");
    
    //get one line
    
    int policy_cnt = 0;
    
    char policy_tb[10][3];
    
    while(1){
        //get command list
        /*
         contents :
         pid / ret / cycle
         */
        int eof, i = 0;
        char line[10];
        while(1){
            char tmp = 0 ;
            eof = fscanf(fp, "%c", &tmp);
            line[i++] = tmp;
            //printf("%c", tmp);
            if(tmp == '\n' || eof == EOF) break;
        }
        if(eof == EOF) break;
        
        policy_tb[policy_cnt][0] = line[0]-'0';
        policy_tb[policy_cnt][1] = line[2]-'0';
        policy_tb[policy_cnt][2] = line[4]-'0';
        
        if(policy_tb[policy_cnt][1] == retention_time &&  policy_tb[policy_cnt][2] == backup_cycle && command == 0){
            printf("The policy already exist\n");
            fclose(fp);
            return 0;
        }
        policy_cnt++;
    }
    
    fclose(fp);
    
    //ssd에 cmd날린다.
    char buf[100];
    char resp[100];
    spm_param sp;
    sp.ret_time = retention_time;
    sp.backup_cycle = backup_cycle;
    sp.version_num = 0;
    sp.cmd = command;
    if(spm_send_cmd(0, buf, 0, resp, policy_cnt, &sp) == -1){
        printf("[spm] error command didn't reach to ssd");
        return 0;
    }
    
    //성공시 파일에 반영
    
    //fp = fopen("policy_list", "w");
    fp = fopen(POLICY_LIST, "w");
    
    for(int i = 0; i < policy_cnt; i++){
        if(command == 1 && policy_tb[policy_cnt][0] == pid){
            policy_tb[policy_cnt][0] = pid;
            policy_tb[policy_cnt][1] = retention_time;
            policy_tb[policy_cnt][2] = backup_cycle;
        }
        fprintf(fp, "%d %d %d\n", policy_tb[i][0], policy_tb[i][1], policy_tb[i][2]);
        printf("%d %d %d\n", policy_tb[i][0], policy_tb[i][1], policy_tb[i][2]);
    }
    
    
    if(command == 0){
        fprintf(fp, "%d %d %d\n", policy_cnt, retention_time, backup_cycle);
        printf("%d %d %d\n", policy_cnt, retention_time, backup_cycle);
    }
    
    fclose(fp);
    
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    return 0;
}

