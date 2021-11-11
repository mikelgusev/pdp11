#include <stdio.h>
#include <rad50.h>
static char cn[]="°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏĞÑÒÓÔÕÖ×ØÙÚÛÜİŞß›œ¥§ƒ„…†—•‘’‹Œ¡£¨¦©¤ª“˜–™”š€‚‡ˆ‰ŠŸ¢ «¬­®¯àáâãäåæçèéêëìíîïğñòóôõö÷øùúûüışÿ";


typedef struct  {     /* FSC-0045 */
    unsigned int onode,dnode,opoint,dpoint;
    char zeros[8];/* 2    2  */
    unsigned int subver,version,onet,dnet;
    char product,rev_lev,password[8];
    unsigned int ozone,dzone;
    char odomain[8],ddomain[8];
    long specific;
} NEWPKT;

typedef struct { /* close to stoneage */ /* 1989 - nnnnn */
	unsigned int orig_node,dest_node,year,month,day,hour,minute,
        second,rate,ver,orig_net,dest_net;
	 char product,rev_lev,password[8];
	 unsigned int qm_orig_zone,qm_dest_zone;
	 char domain[8];
	 unsigned int orig_zone,dest_zone,orig_point,dest_point;
     long pr_data;
} OLDPKT;

typedef struct {               /* FSC-0039 */
	unsigned int orig_node,dest_node,year,month,day,hour,minute,
        second,rate,ver,orig_net,dest_net;
	 char product,rev_lev,password[8];
	 unsigned int qm_orig_zone,qm_dest_zone;
	 char filler[2];
     unsigned int capword2;
     char product2,rev_lev2;
     unsigned int capword,orig_zone,dest_zone,orig_point,dest_point;
     long pr_data;
} MEDPKT;

typedef struct {               /* FSC-0048 */
	unsigned int orig_node,dest_node,year,month,day,hour,minute,
        second,rate,ver,orig_net,dest_net;
	 char product,rev_lev,password[8];
	 unsigned int qm_orig_zone,qm_dest_zone,aux_net;
     unsigned int capword2;
     char product2,rev_lev2;
     unsigned int capword,orig_zone,dest_zone,orig_point,dest_point;
     long pr_data;
} MED2PK;

#define MSGPRIVATE 0x0001  /* private message,          0000 0000 0000 0001 */
#define MSGCRASH   0x0002  /* accept for forwarding     0000 0000 0000 0010 */
#define MSGREAD    0x0004  /* read by addressee         0000 0000 0000 0100 */
#define MSGSENT    0x0008  /* sent OK (remote)          0000 0000 0000 1000 */
#define MSGFILE    0x0010  /* file attached to msg      0000 0000 0001 0000 */
#define MSGFWD     0x0020  /* being forwarded           0000 0000 0010 0000 */
#define MSGORPHAN  0x0040  /* unknown dest node         0000 0000 0100 0000 */
#define MSGKILL    0x0080  /* kill after mailing        0000 0000 1000 0000 */
#define MSGLOCAL   0x0100  /* FidoNet vs. local         0000 0001 0000 0000 */
#define MSGXX1     0x0200  /*                           0000 0010 0000 0000 */
#define MSGXX2     0x0400  /* STRIPPED by FidoNet<tm>   0000 0100 0000 0000 */
#define MSGFRQ     0x0800  /* file request              0000 1000 0000 0000 */
#define MSGRRQ     0x1000  /* receipt requested         0001 0000 0000 0000 */
#define MSGCPT     0x2000  /* is a return receipt       0010 0000 0000 0000 */
#define MSGARQ     0x4000  /* audit trail requested     0100 0000 0000 0000 */
#define MSGURQ     0x8000  /* update request            1000 0000 0000 0000 */

typedef struct {
    unsigned int xonode,xdnode,xonet,xdnet,xattr;
    int          xcost;
} MSGHDR;

static char  attrstr[16][11] = {
	"MSGPRIVATE","MSGCRASH","MSGREAD","MSGSENT","MSGFILE","MSGFWD",
	"MSGORPHAN","MSGKILL","MSGLOCAL","MSGXX1","MSGXX2","MSGFRQ",
	"MSGRRQ","MSGCPT","MSGARQ","MSGURQ"};

FILE	*fp,*fd;
OLDPKT	po;
	NEWPKT	*pn;
	MEDPKT	*pm;
	MED2PK	*pl;
	MSGHDR	mh;
unsigned int	br,ozone,dzone;
unsigned int	anint,x;
long	pos;
char	buffer[128];
char $$prom[]="\15pkt(s)> \200";
int	c;
char	rname[8],name[20];
int	cat[512];

/* main module */
main(argv,argc)
int argv;
char *argc[];
{	int i,seg,*ptr;
	long pos;
	printf("(C) Miha Gusew 1994 PKT-viewer\n");
	pn = (NEWPKT *)&po;
	pl = (MED2PK *)&po;
	pm = (MEDPKT *)&po;
	if(argv==1)
	{
		fprintf(stderr,"Format: '> file.pkt ...' or '> *'\n");
		exit(1);
	}
	if(*argc[1]!='*')
	{
		for(i=1;i<argv;i++) {
			if(frp1(name,argc[i],"dk:",".pkt","\0","dk:msg.pkt"))
				fprintf(stderr,"????? bad file name '%s'",argc[i]);
			else {
			    fp=fopen(name,"rn");
			    fprintf(stderr,"%s\n",name);
			    if(fp==0) fprintf(stderr,"????? Packet '%s' not found",name);
			    else onepkt();
			    fclose(fp);
			}
		}
	}
	else
	{
		fd=fopen("dk:","rnd");
		if(fd==0) fprintf(stderr,"????? DK: directory open error\n");
		else
		{
			seg=1;
			do
			{
				pos=seg+2;
				pos<<=17;
				fseek(fd,pos,0);
				if(fread(cat,2,512,fd)!=512)
				{
					fprintf(stderr,"????? Reading error\n");
					exit(1);
				}
				for(ptr=cat+5;(ptr[0]&0177400)!=04000;ptr+=7+cat[3]/2)
				if(((ptr[0]&0177400)==02000)&&(ptr[3]==RAD50(P,K,T)))
				{
					r50toa(rname, ptr+1, 2);
					i=6;do{rname[i]='\0';}while(rname[--i]==' ');
					fprintf(stderr,"%s\n",rname);
					if(!frp1(name,rname,"dk:",".pkt","\0","dk:msg.pkt"))
					{
					    fp=fopen(name,"rn");
					    if(fp==0) fprintf(stderr,"????? Packet '%s' not found",name);
					    else onepkt();
					    fclose(fp);
					}
				}
			} while(seg=cat[1]);
			fclose(fd);
		}
	}
}


f045()
{
	printf("FSC-0045 (AKA version 2.2) packet:  '%s'\n",fp->io_name);
	printf("From %u:%u/%u.%u@%0.8s to %u:%u/%u.%u@%0.8s\n",	pn->ozone,pn->onet,pn->onode,pn->opoint,pn->odomain,
	pn->dzone,pn->dnet,pn->dnode,pn->dpoint,pn->ddomain);
	printf("Produced by product #%u.%u   Password: '%0.8s'\n",
	pn->product,pn->rev_lev,pn->password);
}


f039()
{
	printf("FSC-0039 (AKA version 2.+) packet:  '%s'\n",fp->io_name);
	ozone = pm->orig_zone;
	dzone = pm->dest_zone;
	if(!ozone) ozone = pm->qm_orig_zone;
	if(!dzone) dzone = pm->qm_dest_zone;
	printf("From %u:%u/%u.%u@???????? to %u:%u/%u.%u@????????\n",
		ozone,pm->orig_net,pm->orig_node,pm->orig_point,
		dzone,pm->dest_net,pm->dest_node,pm->dest_point);
	ozone = pm->product + (pm->product2 << 8);
	dzone = pm->rev_lev + (pm->rev_lev2 << 8);
	printf("Produced by product #%u.%u  Password: '%0.8s'  Capword: %u\n",
		ozone,dzone,pm->password,pm->capword);
}


f048()
{
	printf("FSC-0048 (AKA version 2.N) packet:  '%s'\n",fp->io_name);
	ozone = pl->orig_zone;
	dzone = pl->dest_zone;
	if(!ozone) ozone = pl->qm_orig_zone;
	if(!dzone) dzone = pl->qm_dest_zone;
	if(pl->orig_net != 0177777) {
	    printf("From %u:%u/%u.0@???????? to %u:%u/%u.%u@????????\n",
		ozone,pl->orig_net,pl->orig_node,
		dzone,pl->dest_net,pl->dest_node,pl->dest_point);
	} else {
	    printf("From %u:%u/%u.%u@???????? to %u:%u/%u.%u@????????\n",
		ozone,pl->aux_net,pl->orig_node,pl->orig_point,
		dzone,pl->dest_net,pl->dest_node,pl->dest_point);
	}
	ozone = pl->product + (pl->product2 << 8);
	dzone = pl->rev_lev + (pl->rev_lev2 << 8);
	printf("Produced by product #%u.%u  Password: '%0.8s'  Capword: %u\n",
	                               ozone,dzone,pm->password,pm->capword);
}


fstone()
{
	printf("Stoneage (AKA version 2) packet:  '%s'\n",fp->io_name);
	ozone = po.qm_orig_zone;
	dzone = po.qm_dest_zone;
	if(!ozone) ozone = po.orig_zone;
	if(!dzone) dzone = po.dest_zone;
	printf("From %u:%u/%u.%u@???????? to %u:%u/%u.%u@%????????\n",
		ozone,po.orig_net,po.orig_node,po.orig_point,
		dzone,po.dest_net,po.dest_node,po.dest_point/*,po.domain*/);
	printf("Produced by product #%u.%u  Password: '%0.8s'\n",
		po.product,po.rev_lev,po.password);
}


/* one pkt parse */
onepkt()
{
    br = fread(&po,1,sizeof(OLDPKT),fp);
    if(br < sizeof(OLDPKT)) {
        fprintf(stderr,"Packet %s short:  %u byte%c",fp->io_name,br,br==1?' ':'s');
	return 0;
    }
    if(po.ver != 2) {
        fprintf(stderr,"'%s' not version 2.x; may not be a packet",fp->io_name);
        return 0;
    }
    printf("============================================================\n");
    if(po.rate == 2) { f045(); }
    else if(pm->capword && pm->capword == (~pm->capword2)) { f039();}
    else if(pl->capword && pl->capword == pl->capword2) { f048();}
    else { fstone();}
    printf("============================================================\n");

    for(;;) {
	if(!fread(&anint,sizeof(int),1,fp)) {
	    printf("Unexpected end of packet\n");
	    return 0;
	}
	if(!anint || anint != 2) {
	    if(!anint) { printf("End of packet\n");return 0; }
	    else {
		printf("Grunged packet: attempting resync, expect some garbage");
		fprintf(stderr,"Attempting resync ... synchronisation ...");
		for(;;)
		{
			if(!fread(&anint,sizeof(int),1,fp))
			{
			    printf("SYNC: Unexpected end of packet\n");
			    return 0;
			}
			if(anint == 2)
			{
			    fprintf(stderr," OK\n");
			    break;
			}
		}
	    }
	}
	br = fread(&mh,1,sizeof(mh),fp);
#define	imh	{printf("Incomplete msg header\n");return 0;}
	if(br < sizeof(mh)) imh
	printf("From %u/%u to %u/%u",mh.xonet,mh.xonode,mh.xdnet,mh.xdnode);
	printf("  *  Attrib: %u  Cost: %d\n",mh.xattr,mh.xcost);
	if(mh.xattr) { for(x = 0;x < 16;x++) {
		if(mh.xattr & (1 << x)) printf("%s ",attrstr[x]);
	}}
	br = fgstring(buffer,fp);
	printf("\n");
	if(br==0) imh
	if(strlen(buffer)==19) printf("Date: ");
	else printf("Grunged date: ");
	buffer[19] = 0;
#define	printstring	printf("%s\n",buffer)
	printstring;
	if(fgstring(buffer,fp)==0) imh
	if(strlen(buffer)>35) printf("Grunged to: ");
	else printf("To:   ");
	buffer[35] = 0;
	printstring;
	if(fgstring(buffer,fp)==0) imh;
	if(strlen(buffer) > 35) printf("Grunged from: ");
	else printf("From: ");
	buffer[35] = 0;
	printstring;
	if(fgstring(buffer,fp)==0) imh;
	if(strlen(buffer) > 71) printf("Grunged subj: ");
	else printf("Subj: ");
	buffer[71] = 0;
	printstring;
	while(1){
		c=getc(fp);
		if(c==-1) break;
		if(c=='\0') break;
		c=(c&0200)?cn[c&0177]:c;
		if(c!='\n') {
			if(c=='\r') putchar('\n'); else putchar(c);
		}
	}
        printf("\n------------------------------------------------------------\n");
    }
}

int fgstring(a,f)
char *a;
FILE *f;
{
	int c;
	while(1) {
		c=getc(f);
		if(c=='\0') {*a=0;return 1;}
		if(c==-1) {*a=0;return 0;}
		if(c>0177) c=cn[c&0177];
		*a=c;
		a++;
	}		
}

                                                                                                                                                                                                                                           