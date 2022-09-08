#include "prisign.h"

PriSign::PriSign(PFC *p)
{
    pfc=p;
   // pfc->seed_rng(12345);
}
PriSign::~PriSign()
{

}
int PriSign::Setup(MSK &msk,MPK &mpk)
{
    int ret =0;

    pfc->random(g);
    pfc->random(g_);
    list_reg.count=0;

    //SPS_keyGen
    for(int i=0;i<TKT_NUM_L+1;i++)
    {
        pfc->random(msk.msk_sps.alfa[i]);
        mpk.mpk_sps.beta[i]=pfc->mult(g,msk.msk_sps.alfa[i]);
    }
    pfc->random(mpk.mpk_sps.gama);

    //ABCT key gen
    pfc->random(msk.msk_abct.x);
    mpk.mpk_abct.X_=pfc->mult(g_,msk.msk_abct.x);
    for(int i=0;i<ATTRIBUTES_NUM_Q+1;i++)
    {
        pfc->random(msk.msk_abct.y[i]);
        mpk.mpk_abct.Y_[i]=pfc->mult(g_,msk.msk_abct.y[i]);
    }
    //TIPFE key gen
    mpk.mpk_tipfe.G=pfc->pairing(g_,g);
    pfc->random(msk.msk_tipfe.e);
    mpk.mpk_tipfe.P=pfc->power(mpk.mpk_tipfe.G,msk.msk_tipfe.e);
    for(int i=0;i<CHAR_VECTOR_K;i++)
    {
        pfc->random(msk.msk_tipfe.s[i]);
        mpk.mpk_tipfe.H[i]=pfc->power(mpk.mpk_tipfe.G,msk.msk_tipfe.s[i]);
    }

    return ret;
}

int PriSign::IssuerKeyGen(ISK &isk,IPK &ipk)
{
    int ret =0;
    pfc->random(isk.a);
    ipk.A_=pfc->mult(g_,isk.a);
    for(int i=0;i<TKT_NUM_L;i++)
    {
        pfc->random(isk.b[i]);
        ipk.B[i]=pfc->mult(g,isk.b[i]);
        ipk.B_[i]=pfc->mult(g_,isk.b[i]);
    }
    return ret;
}
int PriSign::IssuerReg_1(ISK &isk,IPK &ipk, Pi5 &pi5)
{
    int ret =0;
    //create zkp pi5
    Big za,zb[TKT_NUM_L];
    G2 Ra,Rb[TKT_NUM_L];

    pfc->random(za);
    Ra=pfc->mult(g_,za);
    for(int i=0;i<TKT_NUM_L;i++)
    {
        pfc->random(zb[i]);
        Rb[i]=pfc->mult(g_,zb[i]);
    }

    pfc->start_hash();
    pfc->add_to_hash(ipk.A_);
    for(int i=0;i<TKT_NUM_L;i++)
        pfc->add_to_hash(ipk.B_[i]);
    pfc->add_to_hash(Ra);
    for(int i=0;i<TKT_NUM_L;i++)
        pfc->add_to_hash(Rb[i]);

    pi5.c=pfc->finish_hash_to_group();

    Big t=pfc->Zpmulti(isk.a,pi5.c);
    pi5.sa=pfc->Zpsub(za,t);
    for(int i=0;i<TKT_NUM_L;i++)
    {
        t=pfc->Zpmulti(isk.b[i],pi5.c);
        pi5.sb[i]=pfc->Zpsub(zb[i],t);
    }
    return ret;
}
int PriSign::IssuerReg_2(MSK &msk,MPK &mpk,IPK &ipk, Pi5 &pi5,SCRED &scred)
{
    int ret=0;
    //verify pi5

    G2 Ra,Rb[TKT_NUM_L];

    Ra=pfc->mult(g_,pi5.sa)+pfc->mult(ipk.A_,pi5.c);
    for(int i=0;i<TKT_NUM_L;i++)
    {
        Rb[i]=pfc->mult(g_,pi5.sb[i])+pfc->mult(ipk.B_[i],pi5.c);
    }

    pfc->start_hash();
    pfc->add_to_hash(ipk.A_);
    for(int i=0;i<TKT_NUM_L;i++)
        pfc->add_to_hash(ipk.B_[i]);
    pfc->add_to_hash(Ra);
    for(int i=0;i<TKT_NUM_L;i++)
        pfc->add_to_hash(Rb[i]);

    Big c=pfc->finish_hash_to_group();
    if(c != pi5.c) return -1;

    //SPS-sign
    Big r;
    pfc->random(r);
    Big inv_r=pfc->Zpinverse(r);
    scred.del1=pfc->mult(g,inv_r);
    G2 T_=mpk.mpk_sps.gama+pfc->mult(g_,msk.msk_sps.alfa[0]);
    scred.del2_=pfc->mult(T_,r);
    T_=pfc->mult(mpk.mpk_sps.gama,msk.msk_sps.alfa[0])+ipk.A_;
    for(int i=0;i<TKT_NUM_L;i++)
    {
        T_=T_+pfc->mult(ipk.B_[i],msk.msk_sps.alfa[i+1]);
    }
    scred.del3_=pfc->mult(T_,r);
    return ret;
}
int PriSign::IssuerReg_3(MPK &mpk,ISK &isk,IPK &ipk,SCRED &scred)
{
    //SPS-verify
    int ret=0;
    GT E1,E2;
    //eq 1
    E1=pfc->pairing(scred.del2_,scred.del1);
    E2=pfc->pairing(mpk.mpk_sps.gama,g)*pfc->pairing(g_,mpk.mpk_sps.beta[0]);
    if(E1 != E2) return -1;
    //eq 2
    E1=pfc->pairing(scred.del3_,scred.del1);
    E2=pfc->pairing(mpk.mpk_sps.gama,mpk.mpk_sps.beta[0])*pfc->pairing(ipk.A_,g);
    for(int i=0;i<TKT_NUM_L;i++)
        E2=E2*pfc->pairing(ipk.B_[i],mpk.mpk_sps.beta[i+1]);
    if(E1 != E2) return -2;
    return ret;
}
//key + f0x+f1x^2+...f(t-1)x^(t-1)
Big PriSign::f_poly(Big f[THRESHOLD_NUM_T-1],Big key,Big x)
{
    Big sum=key;
    Big power_x=x;
    for(int i=0;i<THRESHOLD_NUM_T-1;i++)
    {
        Big T=pfc->Zpmulti(f[i],power_x);
        sum=pfc->Zpadd(sum,T);
        power_x=pfc->Zpmulti(power_x,x);
    }
    return sum;
}
int PriSign::PolMakKeyGen(MSK &msk,MPK &mpk,PSK_LIST &psk_list,PPK_LIST &ppk_list)
{
    int ret=0;
    Big f[THRESHOLD_NUM_T-1];
    //x,xi
    //pfc->random(x);
    for(int k=0;k<THRESHOLD_NUM_T-1;k++)
    {
        pfc->random(f[k]);
    }
    for(int i=0;i<POLICYMAKER_NUM_N;i++)
    {

        psk_list.psk[i].id=i+1;
        psk_list.psk[i].e= f_poly(f,msk.msk_tipfe.e,psk_list.psk[i].id);
        ppk_list.ppk[i].G=mpk.mpk_tipfe.G;
        ppk_list.ppk[i].P=pfc->power(ppk_list.ppk[i].G,psk_list.psk[i].e);

    }
    for(int j=0;j<CHAR_VECTOR_K;j++)
    {
        for(int k=0;k<THRESHOLD_NUM_T-1;k++)
        {
            pfc->random(f[k]);
        }
        for(int i=0;i<POLICYMAKER_NUM_N;i++)
        {

            psk_list.psk[i].s[j]= f_poly(f,msk.msk_tipfe.s[j],psk_list.psk[i].id);
            ppk_list.ppk[i].H[j]=pfc->power(ppk_list.ppk[i].G,psk_list.psk[i].s[j]);
        }
    }
    return ret;
}
int PriSign::IssPolKey(PSK &psk,PPK &ppk,Big &vid,POLICY_V &policy_v,POLICY_KEY &policy_key)
{
    //extract key
    int ret =0;
    Big SUM=0;
    for(int i=0;i<CHAR_VECTOR_K;i++)
    {
        Big T=pfc->Zpmulti(psk.s[i],policy_v.V[i]);
        SUM=pfc->Zpadd(SUM,T);
    }
    pfc->start_hash();
    pfc->add_to_hash(vid);
    policy_key.Theta_vid=pfc->finish_hash_to_group();
    Big T=pfc->Zpmulti(psk.e,policy_key.Theta_vid);
    SUM=pfc->Zpadd(SUM,T);
    policy_key.dk=pfc->mult(g_,SUM);
    return ret;
}
int PriSign::AggrPolKey(PPK_LIST &ppk_list, Big &vid, POLICY_V &policy_v,POLICY_KEY_SHARE_LIST &polkey_list, POLICY_KEY &com_polkey)
{
    int ret=0;
    //tipfe aggre key

    for(int i=0;i<THRESHOLD_NUM_T;i++)
    {
        GT E1,E2;
        E1=pfc->pairing(polkey_list.policy_key[i].dk,g);
        E2=pfc->power(ppk_list.ppk[i].P,polkey_list.policy_key[i].Theta_vid);
        for(int j=0;j<CHAR_VECTOR_K;j++)
            E2=E2*pfc->power(ppk_list.ppk[i].H[j],policy_v.V[j]);
        if(E1 != E2) return -1;
    }
    //compute lamda
    Big lamda[THRESHOLD_NUM_T];
    for(int i=0;i<THRESHOLD_NUM_T;i++)
    {
        Big p=1,q=1;
        for(int j=0;j<THRESHOLD_NUM_T;j++)
        {
            if(i == j)
                continue;
            Big J=j+1;
            Big I=i+1;
            p=pfc->Zpmulti(J,p);

            Big t=pfc->Zpsub(J,I);
            q=pfc->Zpmulti(t,q);
        }
        Big  t=pfc->Zpinverse(q);
        lamda[i]=pfc->Zpmulti(p,t);
    }
    //dk
    com_polkey.Theta_vid=polkey_list.policy_key[0].Theta_vid;
    com_polkey.dk=pfc->mult(g_,0);
    for(int i=0;i<THRESHOLD_NUM_T;i++)
    {
        G2 T=pfc->mult(polkey_list.policy_key[i].dk,lamda[i]);
        com_polkey.dk=com_polkey.dk+T;
    }
    return ret;
}
int PriSign::UserKeyGen(USK &usk,UPK &upk,UTK &utk)
{
    int ret=0;
    pfc->random(usk.usk);
    upk.upk=pfc->mult(g,usk.usk);
    utk.utk=pfc->mult(g_,usk.usk);
    return ret;
}
int PriSign::UserReg_1(Big &uid, USK &usk, UPK &upk, UTK &utk, USER_ATTR &attr, Pi1 &pi1)
{
    int ret=0;
    pfc->random(uid);
    for(int i=0;i<ATTRIBUTES_NUM_Q;i++)
        pfc->random(attr.att[i+1]);
    //compute pi1
    Big z;
    pfc->random(z);
    G1 R1;
    G2 R2;
    R1=pfc->mult(g,z);
    R2=pfc->mult(g_,z);
    pfc->start_hash();
    pfc->add_to_hash(upk.upk);
    pfc->add_to_hash(utk.utk);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pi1.c=pfc->finish_hash_to_group();
    Big t=pfc->Zpmulti(usk.usk,pi1.c);
    pi1.s=pfc->Zpsub(z,t);

    return ret;
}
int PriSign::UserReg_2(MSK &msk, MPK &mpk, Big &uid, UPK &upk, UTK &utk, USER_ATTR &attr, Pi1 &pi1, UCRED &ucred)
{
    int ret=0;
    //verify pi1

    G1 R1;
    G2 R2;
    R1=pfc->mult(g,pi1.s)+pfc->mult(upk.upk,pi1.c);
    R2=pfc->mult(g_,pi1.s)+pfc->mult(utk.utk,pi1.c);
    pfc->start_hash();
    pfc->add_to_hash(upk.upk);
    pfc->add_to_hash(utk.utk);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    Big c=pfc->finish_hash_to_group();
    if(c!=pi1.c) return -1;


    //ABCT credsign
    Big r;
    pfc->random(r);
    ucred.sigma1=pfc->mult(g,r);
    Big t;
    t=pfc->Zpmulti(r,msk.msk_abct.y[0]);
    ucred.sigma2=pfc->mult(upk.upk,t);
    t=msk.msk_abct.x;
    for(int i=0;i<ATTRIBUTES_NUM_Q;i++)
    {
        Big a=pfc->Zpmulti(attr.att[i+1],msk.msk_abct.y[i+1]);
        t=pfc->Zpadd(t,a);
    }
    t=pfc->Zpmulti(t,r);
    ucred.sigma2=ucred.sigma2+pfc->mult(g,t);
    //add reg

    list_reg.info[list_reg.count].uid=uid;
    list_reg.info[list_reg.count].utk.utk=utk.utk;
    list_reg.count++;
    return ret;
}
int PriSign::UserReg_3(MPK &mpk,USK &usk,USER_ATTR &attr,Pi1 &pi1,UCRED &ucred)
{

    int ret=0;
    GT E1,E2;
    attr.att[0]=usk.usk;
    E1=pfc->pairing(g_,ucred.sigma2);
    G2 SUM=mpk.mpk_abct.X_;
    return 0;
    for(int i=0;i<ATTRIBUTES_NUM_Q+1;i++)
    {
        SUM=SUM+pfc->mult(mpk.mpk_abct.Y_[i],attr.att[i]);
    }

    E2=pfc->pairing(SUM,ucred.sigma1);
    if(E1!=E2) return -1;

    return ret;
}
int PriSign::ObtTkt_1(MPK &mpk, USK &usk, UPK &upk, USER_ATTR &attr, UCRED &ucred, TICKET &tick, Pi2 &pi2, Pi3 &pi3, Big &CTX)
{
    int ret=0;
    //abct.show
    Big r1,r2;
    pfc->random(r1);
    pfc->random(r2);
    tick.sigma_1=pfc->mult(ucred.sigma1,r1);
    tick.sigma_2=pfc->mult(ucred.sigma2,r1);
    tick.miu=pfc->mult(tick.sigma_1,usk.usk);
    tick.niu=pfc->mult(tick.sigma_1,r2);
    tick.kappa=mpk.mpk_abct.X_+pfc->mult(g_,r2);
    for(int i=0;i<DISCLOSE_NUM_D;i++)
        tick.dis.att[i]=attr.att[i+1];
    for(int i=0;i<ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D;i++)
    {
        tick.kappa=tick.kappa+pfc->mult(mpk.mpk_abct.Y_[i+DISCLOSE_NUM_D+1],attr.att[i+DISCLOSE_NUM_D+1]);
    }
    //compute pi_2
    Big zk,z2,t[ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D];
    pfc->random(zk);
    pfc->random(z2);
    for(int i=0;i<ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D;i++)
        pfc->random(t[i]);
    G1 R1,R2;
    G2 R3;
    R1=pfc->mult(tick.sigma_1,zk);
    R2=pfc->mult(tick.sigma_1,z2);
    R3=pfc->mult(g_,z2);
    for(int i=0;i<ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D;i++)
        R3=R3+pfc->mult(mpk.mpk_abct.Y_[DISCLOSE_NUM_D+i+1],t[i]);
    pfc->start_hash();
    pfc->add_to_hash(tick.sigma_1);
    pfc->add_to_hash(mpk.mpk_abct.X_);
    for(int i=0;i<ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D;i++)
        pfc->add_to_hash(mpk.mpk_abct.Y_[DISCLOSE_NUM_D+i+1]);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    pfc->add_to_hash(CTX);
    pi2.c=pfc->finish_hash_to_group();

    Big tt=pfc->Zpmulti(usk.usk,pi2.c);
    pi2.sk=pfc->Zpsub(zk,tt);
    tt=pfc->Zpmulti(r2,pi2.c);
    pi2.s2=pfc->Zpsub(z2,tt);
    for(int i=0;i<ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D;i++)
    {
        tt=pfc->Zpmulti(attr.att[DISCLOSE_NUM_D+i+1],pi2.c);
        pi2.sm[i]=pfc->Zpsub(t[i],tt);

    }
#if 0
    pi2.R1=R1;
    pi2.R2=R2;
    pi2.R3=R3;
#endif
    //preblind

    pfc->random(tick.d);
    tick.D=pfc->mult(g,tick.d);
    pfc->start_hash();
    pfc->add_to_hash(tick.D);
    pfc->add_to_hash(CTX);
    tick.h=pfc->mult(g,pfc->finish_hash_to_group());
    Big r;
    pfc->random(tick.sn);
    pfc->random(r);
    tick.C0=pfc->mult(g,r);
    tick.C1=pfc->mult(tick.D,r)+pfc->mult(tick.h,tick.sn);

    //compute pi3
    Big zd,zr,zm;
    pfc->random(zd);
    pfc->random(zr);
    pfc->random(zm);
    G1 Rd,Rr,Rm;
    Rd=pfc->mult(g,zd);
    Rr=pfc->mult(g,zr);
    Rm=pfc->mult(tick.D,zr)+pfc->mult(tick.h,zm);
    pfc->start_hash();
    pfc->add_to_hash(tick.D);
    pfc->add_to_hash(tick.h);
    pfc->add_to_hash(tick.C0);
    pfc->add_to_hash(tick.C1);
    pfc->add_to_hash(Rd);
    pfc->add_to_hash(Rr);
    pfc->add_to_hash(Rm);
    pfc->add_to_hash(CTX);
    pi3.c=pfc->finish_hash_to_group();
    tt=pfc->Zpmulti(tick.d,pi3.c);
    pi3.sd=pfc->Zpsub(zd,tt);
    tt=pfc->Zpmulti(r,pi3.c);
    pi3.sr=pfc->Zpsub(zr,tt);
    tt=pfc->Zpmulti(tick.sn,pi3.c);
    pi3.sm=pfc->Zpsub(zm,tt);

    return ret;
}
int PriSign::ObtTkt_2(MPK &mpk,ISK &isk,IPK &ipk,TICKET &tick,Pi2 &pi2,Pi3 &pi3,Big &CTX)
{
    int ret=0;
    //ABCT verify
    //pi2 verify
    G1 R1,R2;
    G2 R3;
    R1=pfc->mult(tick.sigma_1,pi2.sk)+pfc->mult(tick.miu,pi2.c);
    R2=pfc->mult(tick.sigma_1,pi2.s2)+pfc->mult(tick.niu,pi2.c);
    R3=pfc->mult(g_,pi2.s2);
    for(int i=0;i<ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D;i++)
        R3=R3+pfc->mult(mpk.mpk_abct.Y_[DISCLOSE_NUM_D+i+1],pi2.sm[i]);
    G2 T=tick.kappa+(-mpk.mpk_abct.X_);
    T=pfc->mult(T,pi2.c);
    R3=R3+T;

#if 0
    if(R1!=pi2.R1) return 1;
    if(R2!=pi2.R2) return 2;
    if(R3!=pi2.R3) return 3;

#endif

    pfc->start_hash();
    pfc->add_to_hash(tick.sigma_1);
    pfc->add_to_hash(mpk.mpk_abct.X_);
    for(int i=0;i<ATTRIBUTES_NUM_Q-DISCLOSE_NUM_D;i++)
        pfc->add_to_hash(mpk.mpk_abct.Y_[DISCLOSE_NUM_D+i+1]);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    pfc->add_to_hash(CTX);
    Big c=pfc->finish_hash_to_group();
    if(c!=pi2.c) return -1;

    //eq
    G1 T1;
    GT E1,E2;
    T1=tick.sigma_2+tick.niu;
    E1=pfc->pairing(g_,T1);
    E2=pfc->pairing(mpk.mpk_abct.Y_[0],tick.miu);
    G2 T2;
    T2=tick.kappa;

    for(int i=0;i<DISCLOSE_NUM_D;i++)
        T2=T2+pfc->mult(mpk.mpk_abct.Y_[i+1],tick.dis.att[i]);
    E2=E2*pfc->pairing(T2,tick.sigma_1);
    if(E1!=E2) return -2;



    //ABCB blindsign
    //pi3 verify

    G1 Rd,Rr,Rm;
    Rd=pfc->mult(g,pi3.sd)+pfc->mult(tick.D,pi3.c);
    Rr=pfc->mult(g,pi3.sr)+pfc->mult(tick.C0,pi3.c);
    Rm=pfc->mult(tick.D,pi3.sr)+pfc->mult(tick.h,pi3.sm)+pfc->mult(tick.C1,pi3.c);
    pfc->start_hash();
    pfc->add_to_hash(tick.D);
    pfc->add_to_hash(tick.h);
    pfc->add_to_hash(tick.C0);
    pfc->add_to_hash(tick.C1);
    pfc->add_to_hash(Rd);
    pfc->add_to_hash(Rr);
    pfc->add_to_hash(Rm);
    pfc->add_to_hash(CTX);
    c=pfc->finish_hash_to_group();
    if(c!=pi3.c) return -3;

    //sign VP
    pfc->random(tick.VP);
    tick.tau1=pfc->mult(tick.h,isk.a)+pfc->mult(tick.C1,isk.b[0])+pfc->mult(tick.h,pfc->Zpmulti(tick.VP,isk.b[1]));
    tick.tau2=pfc->mult(tick.C0,isk.b[0]);
    return ret;
}
int PriSign::ObtTkt_3(MPK &mpk,IPK &ipk,TICKET &tick)
{
    int ret=0;
    tick.tau2=tick.tau1+pfc->mult(tick.tau2,-tick.d);
    tick.tau1=tick.h;
    GT E1,E2;
    E1=pfc->pairing(g_,tick.tau2);
    G2 T;
    T=ipk.A_+pfc->mult(ipk.B_[0],tick.sn)+pfc->mult(ipk.B_[1],tick.VP);
    E2=pfc->pairing(T,tick.tau1);
    if(E1 != E2) return -1;

    return ret;
}
int PriSign::Trace(MSK &msk,TICKET &tick,Big &uid)
{
    int ret=0;
  //  printf("\nlist_reg.count = %d\n",list_reg.count);
    for(int i=0;i<list_reg.count;i++)
    {
        GT E1,E2;
        E1=pfc->pairing(g_,tick.miu);
        E2=pfc->pairing(list_reg.info[i].utk.utk,tick.sigma_1);
        if(E1 == E2)
        {
            uid=list_reg.info[i].uid;
            return ret;
        }
    }
    return -1;
}
int PriSign::Show(MPK &mpk,ATTR_U &U,TICKET &tick,TOKEN &token)
{
    int ret=0;
    Big r;
    pfc->random(r);
    token.sn=tick.sn;
    token.VP=tick.VP;
    token.tau1=pfc->mult(tick.tau1,r);
    token.tau2=pfc->mult(tick.tau2,r);
    //encrypt
    G1 T1;
    G2 T2;
    pfc->random(T1);
    pfc->random(T2);
    token.K=pfc->pairing(T2,T1);
    Big k;
    pfc->random(k);
    token.C0=token.K*pfc->power(mpk.mpk_tipfe.P,k);
    token.C1=pfc->mult(g,k);
    for(int i=0;i<CHAR_VECTOR_K;i++)
    {
        token.C2[i]=pfc->power(mpk.mpk_tipfe.H[i],k)*pfc->power(mpk.mpk_tipfe.G,U.u[i]);
    }
    return ret;
}
int PriSign::Verify(MPK &mpk,IPK &ipk,POLICY_V &policy_v,POLICY_KEY &com_polkey,TOKEN &token)
{
    int ret=0;
    //decrypt
    Big inv_theta=pfc->Zpinverse(com_polkey.Theta_vid);
    GT M=pfc->power(token.C2[0],policy_v.V[0]);
    for(int i=1;i<CHAR_VECTOR_K;i++)
        M=M*pfc->power(token.C2[i],policy_v.V[i]);
    GT E;
    E=pfc->pairing(com_polkey.dk,token.C1);
    E=pfc->power(M/E,inv_theta);
    GT K=E*token.C0;
    if(K!=token.K) return -1;
    //ABCB verify

    GT E1,E2;
    E1=pfc->pairing(g_,token.tau2);
    G2 T=ipk.A_+pfc->mult(ipk.B_[0],token.sn)+pfc->mult(ipk.B_[1],token.VP);
    E2=pfc->pairing(T,token.tau1);
    if(E1 !=E2) return -2;

    return ret;
}
