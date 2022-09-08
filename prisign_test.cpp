#include"prisign.h"
#include "pairing_3.h"
#include <ctime>
#include <time.h>
#define TEST_TIME 1

int correct_test()
{
    PFC pfc(AES_SECURITY);
    PriSign prisign(&pfc);
    //1 SetUP
    MSK msk;
    MPK mpk;
    int ret=0;
    //Setup
    ret = prisign.Setup(msk,mpk);
    if(ret != 0)
    {
        printf("prisign.Setup Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.Setup pass\n");

    ISK isk;
    IPK ipk;
    ret = prisign.IssuerKeyGen(isk,ipk);
    if(ret != 0)
    {
        printf("prisign.IssuerKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.IssuerKeyGen pass\n");
    Pi5 pi5;
    ret = prisign.IssuerReg_1(isk,ipk, pi5);
    if(ret != 0)
    {
        printf("prisign.IssuerReg_1 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.IssuerReg_1 pass\n");
    SCRED scred;
    ret = prisign.IssuerReg_2(msk,mpk,ipk, pi5,scred);
    if(ret != 0)
    {
        printf("prisign.IssuerReg_2 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.IssuerReg_2 pass\n");
    ret = prisign.IssuerReg_3(mpk,isk,ipk,scred);
    if(ret != 0)
    {
        printf("prisign.IssuerReg_3 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.IssuerReg_3 pass\n");

    PSK_LIST psk_list;
    PPK_LIST ppk_list;
    ret = prisign.PolMakKeyGen(msk,mpk,psk_list,ppk_list);
    if(ret != 0)
    {
        printf("prisign.PolMakKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.PolMakKeyGen pass\n");
    Big vid;
    pfc.random(vid);
    POLICY_V policy_v;
    policy_v.V[0]=1;
    policy_v.V[1]=0;
    policy_v.V[2]=1;
    policy_v.V[3]=0;
    policy_v.V[4]=1;
    POLICY_KEY_SHARE_LIST polkey_list;
    for(int i=0;i<THRESHOLD_NUM_T;i++)
    {
        ret = prisign.IssPolKey( psk_list.psk[i], ppk_list.ppk[i],vid,policy_v,polkey_list.policy_key[i]);
        if(ret != 0)
        {
            printf("prisign.IssPolKey i=[%d] Erro ret =%d\n",i,ret);
            return 1;
        }
        else
            printf("prisign.IssPolKey i=[%d] pass\n",i);
    }
    POLICY_KEY com_polkey;
    ret = prisign.AggrPolKey(ppk_list,vid,policy_v,polkey_list,com_polkey);
    if(ret != 0)
    {
        printf("prisign.AggrPolKey Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.AggrPolKey pass\n");

    Big uid;
    USK usk;
    UPK upk;
    UTK utk;
    USER_ATTR attr;
    Pi1 pi1;
    ret = prisign.UserKeyGen(usk,upk,utk);
    if(ret != 0)
    {
        printf("prisign.UserKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.UserKeyGen pass\n");
    pfc.random(uid);

    ret = prisign.UserReg_1(uid,usk,upk,utk,attr,pi1);
    if(ret != 0)
    {
        printf("prisign.UserReg_1 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.UserReg_1 pass\n");
    UCRED ucred;
    ret = prisign.UserReg_2(msk,mpk,uid,upk,utk,attr,pi1,ucred);
    if(ret != 0)
    {
        printf("prisign.UserReg_2 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.UserReg_2 pass\n");

    ret = prisign.UserReg_3(mpk,usk,attr,pi1,ucred);
    if(ret != 0)
    {
        printf("prisign.UserReg_3 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.UserReg_3 pass\n");

    TICKET tick;
    Pi2 pi2;
    Pi3 pi3;
    Big CTX_1;
    pfc.random(CTX_1);
    ret = prisign.ObtTkt_1(mpk,usk,upk,attr,ucred,tick,pi2,pi3,CTX_1);
    if(ret != 0)
    {
        printf("prisign.ObtTkt_1 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.ObtTkt_1 pass\n");
    ret = prisign.ObtTkt_2(mpk,isk,ipk,tick,pi2,pi3,CTX_1);
    if(ret != 0)
    {
        printf("prisign.ObtTkt_2 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.ObtTkt_2 pass\n");
    ret = prisign.ObtTkt_3(mpk,ipk,tick);
    if(ret != 0)
    {
        printf("prisign.ObtTkt_3 Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.ObtTkt_3 pass\n");
    Big tuid;
    ret = prisign.Trace(msk,tick,tuid);
    if(ret != 0)
    {
        printf("prisign.Trace Erro ret =%d\n",ret);
        return 1;
    }
    else
    {
        if(uid==tuid)
            printf("prisign.Trace pass\n");
        else
        {
            printf("prisign.Trace something Erro\n");
            return 1;
        }
    }

    ATTR_U U;
    U.u[0]=0;
    U.u[1]=1;
    U.u[2]=0;
    U.u[3]=1;
    U.u[4]=0;
    TOKEN token;
    ret = prisign.Show(mpk,U,tick,token);
    if(ret != 0)
    {
        printf("prisign.Show Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.Show pass\n");

    ret = prisign.Verify(mpk,ipk,policy_v,com_polkey,token);
    if(ret != 0)
    {
        printf("prisign.Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("prisign.Verify pass\n");

    return 0;
}
int speed_test()
{
    int i;
    clock_t start,finish;
    double sum;
    PFC pfc(AES_SECURITY);
    PriSign prisign(&pfc);
    //1 SetUP
    MSK msk;
    MPK mpk;
    int ret=0;
    //Setup
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.Setup(msk,mpk);
        if(ret != 0)
        {
            printf("prisign.Setup Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.Setup ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    ISK isk;
    IPK ipk;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.IssuerKeyGen(isk,ipk);
        if(ret != 0)
        {
            printf("prisign.IssuerKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.IssuerKeyGen ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    Pi5 pi5;

    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.IssuerReg_1(isk,ipk, pi5);
        if(ret != 0)
        {
            printf("prisign.IssuerReg_1 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.IssuerReg_1 ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    SCRED scred;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.IssuerReg_2(msk,mpk,ipk, pi5,scred);
        if(ret != 0)
        {
            printf("prisign.IssuerReg_2 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.IssuerReg_2 ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.IssuerReg_3(mpk,isk,ipk,scred);
        if(ret != 0)
        {
            printf("prisign.IssuerReg_3 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.IssuerReg_3 ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    PSK_LIST psk_list;
    PPK_LIST ppk_list;
    start=clock();
    ret = prisign.PolMakKeyGen(msk,mpk,psk_list,ppk_list);
    if(ret != 0)
    {
        printf("prisign.PolMakKeyGen Erro ret =%d\n",ret);
        return 1;
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.PolMakKeyGen ret : %d time =%f sec\n",ret,sum/1);
    Big vid;
    pfc.random(vid);
    POLICY_V policy_v;
    policy_v.V[0]=1;
    policy_v.V[1]=0;
    policy_v.V[2]=1;
    policy_v.V[3]=0;
    policy_v.V[4]=1;
    POLICY_KEY_SHARE_LIST polkey_list;
    for(int i=0;i<THRESHOLD_NUM_T;i++)
    {
        start=clock();

        ret = prisign.IssPolKey( psk_list.psk[i], ppk_list.ppk[i],vid,policy_v,polkey_list.policy_key[i]);
        if(ret != 0)
        {
            printf("prisign.IssPolKey i=[%d] Erro ret =%d\n",i,ret);
            return 1;
        }

        finish=clock();
        sum = (double)(finish-start)/CLOCKS_PER_SEC;
        printf("prisign.IssPolKey i=[%d] ret : %d time =%f sec\n",i,ret,sum/1);
    }
    POLICY_KEY com_polkey;
    start=clock();

    ret = prisign.AggrPolKey(ppk_list,vid,policy_v,polkey_list,com_polkey);
    if(ret != 0)
    {
        printf("prisign.AggrPolKey Erro ret =%d\n",ret);
        return 1;
    }

    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.AggrPolKey ret : %d time =%f sec\n",ret,sum/1);

    Big uid;
    USK usk;
    UPK upk;
    UTK utk;
    USER_ATTR attr;
    Pi1 pi1;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.UserKeyGen(usk,upk,utk);
        if(ret != 0)
        {
            printf("prisign.UserKeyGen Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.UserKeyGen ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    pfc.random(uid);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.UserReg_1(uid,usk,upk,utk,attr,pi1);
        if(ret != 0)
        {
            printf("prisign.UserReg_1 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.UserReg_1 ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    UCRED ucred;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.UserReg_2(msk,mpk,uid,upk,utk,attr,pi1,ucred);
        if(ret != 0)
        {
            printf("prisign.UserReg_2 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.UserReg_2 ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.UserReg_3(mpk,usk,attr,pi1,ucred);
        if(ret != 0)
        {
            printf("prisign.UserReg_3 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.UserReg_3 ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    TICKET tick;
    Pi2 pi2;
    Pi3 pi3;
    Big CTX_1;
    pfc.random(CTX_1);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.ObtTkt_1(mpk,usk,upk,attr,ucred,tick,pi2,pi3,CTX_1);
        if(ret != 0)
        {
            printf("prisign.ObtTkt_1 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.ObtTkt_1 ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.ObtTkt_2(mpk,isk,ipk,tick,pi2,pi3,CTX_1);
        if(ret != 0)
        {
            printf("prisign.ObtTkt_2 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.ObtTkt_2 ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.ObtTkt_3(mpk,ipk,tick);
        if(ret != 0)
        {
            printf("prisign.ObtTkt_3 Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.ObtTkt_3 ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    Big tuid;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.Trace(msk,tick,tuid);
        if(ret != 0)
        {
            printf("prisign.Trace Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.Trace ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    ATTR_U U;
    U.u[0]=0;
    U.u[1]=1;
    U.u[2]=0;
    U.u[3]=1;
    U.u[4]=0;
    TOKEN token;
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.Show(mpk,U,tick,token);
        if(ret != 0)
        {
            printf("prisign.Show Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.Show ret : %d time =%f sec\n",ret,sum/TEST_TIME);
    start=clock();
    for(i=0;i<TEST_TIME;i++)
    {
        ret = prisign.Verify(mpk,ipk,policy_v,com_polkey,token);
        if(ret != 0)
        {
            printf("prisign.Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/CLOCKS_PER_SEC;
    printf("prisign.Verify ret : %d time =%f sec\n",ret,sum/TEST_TIME);

    return 0;
}
int main()
{
#if 1
    int ret =correct_test();
    if(ret != 0)
    {

        printf("PriSign correct_test Erro ret =%d\n",ret);
        return 1;
    }
    else
    {
        printf("*******************************************\n");
        printf("PriSign correct_test pass\n");
    }
#endif
    ret =speed_test();
    if(ret != 0)
    {
        printf("PriSign speed_test Erro ret =%d\n",ret);
        return 1;
    }
    else
    {
        printf("*******************************************\n");
        printf("PriSign speed_test pass\n");
    }
    return 0;
}
