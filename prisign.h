#ifndef PRISIGN_H
#define PRISIGN_H

#include"pairing_3.h"
#include "zzn.h"
#include <stdlib.h>
#include <list>
#include <stdio.h>
typedef unsigned char u8;
typedef unsigned int u32;

#define AES_SECURITY 128
#define USER_NUM 10
#define ATTRIBUTES_NUM_Q 10
#define DISCLOSE_NUM_D 3
#define POLICYMAKER_NUM_N 5
#define THRESHOLD_NUM_T 3
#define CHAR_VECTOR_K 5
#define TKT_NUM_L 2


struct MSK_SPS
{
    Big alfa[TKT_NUM_L+1];

};
struct MSK_ABCT
{
    Big x,y[ATTRIBUTES_NUM_Q+1];

};
struct MSK_TIPFE
{
    Big s[CHAR_VECTOR_K];
    Big e;

};
struct MPK_SPS
{
    G2 gama;
    G1 beta[TKT_NUM_L+1];

};
struct MPK_ABCT
{
    G2 X_,Y_[ATTRIBUTES_NUM_Q+1];

};
struct MPK_TIPFE
{
    GT G,P,H[CHAR_VECTOR_K];
};
struct MSK
{
    MSK_SPS msk_sps;
    MSK_ABCT msk_abct;
    MSK_TIPFE msk_tipfe;

};

struct MPK
{
    MPK_SPS mpk_sps;
    MPK_ABCT mpk_abct;
    MPK_TIPFE mpk_tipfe;

};
struct ISK
{
    Big a,b[TKT_NUM_L];
};
struct IPK
{
    G2 A_;
    G1 B[TKT_NUM_L];
    G2 B_[TKT_NUM_L];
};
struct Pi5
{
    Big c,sa,sb[TKT_NUM_L];

};
struct SCRED
{
    G1 del1;
    G2 del2_,del3_;
};
struct PSK
{
    Big id;
  //  Big Thetaid;
    Big s[CHAR_VECTOR_K];
    Big e;


};
struct PPK
{
    Big id;
    GT G,P,H[CHAR_VECTOR_K];

};
struct PSK_LIST
{
     PSK psk[POLICYMAKER_NUM_N];
};
struct PPK_LIST
{
    PPK ppk[POLICYMAKER_NUM_N];
};
struct POLICY_V
{
    Big V[CHAR_VECTOR_K];

};
struct POLICY_KEY
{
    Big Theta_vid;
    G2 dk;

};
struct POLICY_KEY_SHARE_LIST
{
    POLICY_KEY policy_key[THRESHOLD_NUM_T];
};
struct USK
{
    Big usk;

};
struct UPK
{
    G1 upk;
};
struct UTK
{
    G2 utk;
};
struct USER_ATTR
{
    Big att[ATTRIBUTES_NUM_Q+1];
};
struct DIS_ATTR
{
    Big att[DISCLOSE_NUM_D];
};
struct Pi1
{
    Big c,s;

};
struct UCRED
{
    G1 sigma1,sigma2;
};
struct INFOR
{
    Big uid;
    UTK utk;

};
struct LIST_REG
{
    int count;
    INFOR info[USER_NUM];
};
struct Pi2
{
    Big c,sk,s2,sm[ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D];
#if 0
    G1 R1,R2;
    G2 R3;

#endif

};
struct TICKET
{
    Big sn;
    Big VP;
    Big d;
    G1 D;
    DIS_ATTR dis;
    G1 sigma_1;
    G1 sigma_2;
    G1 miu,niu;
    G2 kappa;
    G1 C0,C1,h;
    G1 tau1,tau2;
};
struct Pi3
{
    Big c,sd,sr,sm;

};

struct ATTR_U
{
    Big u[CHAR_VECTOR_K];
};

struct TOKEN
{
    Big sn;
    Big VP;
    G1 tau1,tau2;
    GT K;
    GT C0,C2[CHAR_VECTOR_K];
    G1 C1;
};

class PriSign
{
private:
    PFC *pfc;
    G1 g;
    G2 g_;
    LIST_REG list_reg;
    Big f_poly(Big f[THRESHOLD_NUM_T-1],Big key,Big x);
public:
    PriSign(PFC *p);
    ~PriSign();
    int Setup(MSK &msk,MPK &mpk);
    int IssuerKeyGen(ISK &isk,IPK &ipk);
    int IssuerReg_1(ISK &isk,IPK &ipk, Pi5 &pi5);
    int IssuerReg_2(MSK &msk,MPK &mpk,IPK &ipk, Pi5 &pi5,SCRED &scred);
    int IssuerReg_3(MPK &mpk,ISK &isk,IPK &ipk,SCRED &scred);
    int PolMakKeyGen(MSK &msk,MPK &mpk,PSK_LIST &psk_list,PPK_LIST &ppk_list);
    int IssPolKey(PSK &psk,PPK &ppk,Big &vid,POLICY_V &policy_v,POLICY_KEY &policy_key);
    int AggrPolKey(PPK_LIST &ppk_list,Big &vid,POLICY_V &policy_v,POLICY_KEY_SHARE_LIST &polkey_list,POLICY_KEY &com_polkey);
    int UserKeyGen(USK &usk,UPK &upk,UTK &utk);
    int UserReg_1(Big &uid,USK &usk,UPK &upk,UTK &utk,USER_ATTR &attr,Pi1 &pi1);
    int UserReg_2(MSK &msk,MPK &mpk,Big &uid,UPK &upk,UTK &utk,USER_ATTR &attr,Pi1 &pi1,UCRED &ucred);
    int UserReg_3(MPK &mpk,USK &usk,USER_ATTR &attr,Pi1 &pi1,UCRED &ucred);
    int ObtTkt_1(MPK &mpk,USK &usk,UPK &upk,USER_ATTR &attr,UCRED &ucred,TICKET &tick,Pi2 &pi2,Pi3 &pi3,Big &CTX);
    int ObtTkt_2(MPK &mpk,ISK &isk,IPK &ipk,TICKET &tick,Pi2 &pi2,Pi3 &pi3,Big &CTX);
    int ObtTkt_3(MPK &mpk,IPK &ipk,TICKET &tick);
    int Trace(MSK &msk,TICKET &tick,Big &uid);
    int Show(MPK &mpk,ATTR_U &U,TICKET &tick,TOKEN &token);
    int Verify(MPK &mpk,IPK &ipk,POLICY_V &policy_v,POLICY_KEY &com_polkey,TOKEN &token);

};

#endif // PRISIGN_H
