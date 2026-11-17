#include <winsock2.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static const char A[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn0123456789";
static uint32_t T[8];
static volatile int found;
static char result[6];

static inline int sha5_match(const char *s){
    uint32_t w[64];
    w[0]=((uint32_t)(uint8_t)s[0]<<24)|((uint32_t)(uint8_t)s[1]<<16)|((uint32_t)(uint8_t)s[2]<<8)|(uint8_t)s[3];
    w[1]=((uint32_t)(uint8_t)s[4]<<24)|0x00800000u;
    for(int i=2;i<15;i++) w[i]=0;
    w[15]=40;
    for(int i=16;i<64;i++){
        uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=0x6a09e667,b=0xbb67ae85,c=0x3c6ef372,d=0xa54ff53a,
             e=0x510e527f,f=0x9b05688c,g=0x1f83d9ab,h=0x5be0cd19;
    for(int i=0;i<64;i++){
        uint32_t S1=ROR(e,6)^ROR(e,11)^ROR(e,25);
        uint32_t ch=(e&f)^(~e&g);
        uint32_t t1=h+S1+ch+K[i]+w[i];
        uint32_t S0=ROR(a,2)^ROR(a,13)^ROR(a,22);
        uint32_t mj=(a&b)^(a&c)^(b&c);
        uint32_t t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    return (a+0x6a09e667u==T[0]) && (b+0xbb67ae85u==T[1]) &&
           (c+0x3c6ef372u==T[2]) && (d+0xa54ff53au==T[3]) &&
           (e+0x510e527fu==T[4]) && (f+0x9b05688cu==T[5]) &&
           (g+0x1f83d9abu==T[6]) && (h+0x5be0cd19u==T[7]);
}

static int solve(const char *hex){
    for(int i=0;i<8;i++){ char t[9]; memcpy(t,hex+8*i,8); t[8]=0; T[i]=(uint32_t)strtoul(t,0,16); }
    found=0;
    #pragma omp parallel for schedule(dynamic,1)
    for(int a=0;a<50;a++){
        char s[6]={0}; s[0]=A[a];
        for(int b=0;b<50 && !found;b++){ if(b==a)continue; s[1]=A[b];
        for(int c=0;c<50 && !found;c++){ if(c==a||c==b)continue; s[2]=A[c];
        for(int d=0;d<50;d++){ if(d==a||d==b||d==c)continue; s[3]=A[d];
        for(int e=0;e<50;e++){ if(e==a||e==b||e==c||e==d)continue; s[4]=A[e];
            if(sha5_match(s)){
                #pragma omp critical
                { if(!found){ found=1; memcpy(result,s,6); } }
            }
        }}}}
    }
    return found;
}

static int readline(SOCKET s, char *buf, int max){
    int n=0; char ch;
    while(n<max-1){
        int r=recv(s,&ch,1,0);
        if(r<=0) break;
        if(ch=='\n') break;
        buf[n++]=ch;
    }
    buf[n]=0;
    return n;
}

int main(void){
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    DWORD timeout=170000;
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof timeout);

    struct sockaddr_in addr={0};
    addr.sin_family=AF_INET;
    addr.sin_port=htons(31338);
    addr.sin_addr.s_addr=inet_addr("202.61.227.83");
    if(connect(s,(struct sockaddr*)&addr,sizeof addr)!=0){ printf("Conexiune esuata\n"); return 1; }

    char line[512];
    for(int round=1;round<=5;round++){
        char *p=NULL;
        while(1){
            if(readline(s,line,sizeof line)==0){ printf("Conexiune inchisa\n"); return 1; }
            printf("%s\n",line);
            p=strstr(line,"== ");
            if(strstr(line,"sha256") && p) break;
        }
        p+=3;
        if(strlen(p)<64){ printf("bad hash line\n"); return 1; }
        char hex[65]; memcpy(hex,p,64); hex[64]=0;

        readline(s,line,sizeof line);
        printf("%s\n",line);

        DWORD t0=GetTickCount();
        if(!solve(hex)){ printf("nicio solutie gasita\n"); return 1; }
        printf("round %d: %s (%lu ms)\n",round,result,GetTickCount()-t0);

        char out[16]; snprintf(out,sizeof out,"%s\n",result);
        send(s,out,(int)strlen(out),0);
    }

    while(readline(s,line,sizeof line)>0) printf("%s\n",line);
    closesocket(s); WSACleanup();
    return 0;
}