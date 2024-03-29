#include <stdio.h>
#include <rad50.h>

FILE *fp,*fo,*fb;

char dvnam[20],flnam[20],name[40],banner[40];
char *buj,*buc,*bc;
int filsiz,blen;
char $$prom[]="\15ban> \200";

struct rec
{
	char *line;
	int size;
	struct rec *next;
} frec,*lrec,*arec;


/* main module */
main(n,a)
char *a[];
{
	int np,i,j;
	char *dp,*df,*kp,*nam;
	printf("(C) Miha Gusew 1994, Insert your own banner to the Zip files\n");
	if(n==1)
	{
		printf("Use like:\n");
		printf("ban> pattern[.zip] ... -keys\n");
		printf("Keys is -bbanner  - set banner name (sy:banner.alt)\n");
		exit(1);
	}
	stos("sy:banner.alt",banner);
	frec.next=0;
	lrec=(&frec);
	for(np=1;np<n;np++)
		if(*a[np]=='-')
			for(kp=a[np]+1;*kp;kp++)
				switch(*kp)
				{
				case 'b':
				case 'B':
					stos(kp+1,banner);
					*(kp+1)='\0';
					break;
				default: printf("Key '%c' ignored\n",*kp);
				}
	printf("Banner name: '%s'\n",banner);
	buj=malloc(8192);
	buc=malloc(8192);
	if((!buj)||(!buc))
	{
		printf("�� ���� ��������� ������.\n");
		exit(1);
	}
	fb=fopen(banner,"rn");
	if(!fb)
	{
		printf("Banner not found\n");
		exit(1);
	}
	bc=buc;
	for(i=0;i<8192;i++)
	{
		j=getc(fb);
		if((j==0)||(j==(-1))) break;
		*bc++=j;
	}
	fclose(fb);
	if(i==0)
	{
		printf("Banner is empty");
		exit(1);
	}
	blen=i;
	printf("Banner size: %d bytes\n",blen);
	for(np=1;np<n;np++)
	{
		if(*a[np]!='-')
		{
			parnam(dvnam,flnam,a[np]);
			printf("#pattern [%s][%s]\n",dvnam,flnam);
			dvopen(dvnam);
			while(dp=dvnext())
			{
				printf("#device [%s]\n",dp);
				if(dropen(dp)) while(df=drnext())
				{
					if(patmat(trim(df),flnam))
					{
						buildname(dp,trim(df),name);
						printf("%% %s\n",name);
						arec=malloc(sizeof(struct rec));
						if(!arec)
						{
							fprintf(stderr,"Can't store all file names\n");
						}
						else
						{
							arec->line=strdup(name);
							arec->next=0;
							arec->size=filsiz;
							lrec->next=arec;
							lrec=arec;
						}
					}
				}
			}
		}
	}
	arec=(&frec);
	while(arec=arec->next)
	{
		stos(arec->line,name);
		filsiz=arec->size;
		fprintf(stderr,"& %s\n",name);
		fp=fopen(name,"rn");
		fo=fopen(name,"wn");
		if(fp&&fo) oneban();
		else printf("????? Can't open '%s' for read or write\n",name);
		fclose(fp);
	}
}



long posi,aa,bb;

oneban()
{
	int a,b,i,s,blk;
	if(filsiz==0)
	{
		printf("File size=0. No banner: '%s'\n",name);
		fpurge(fo);
		return;
	}
	a=getc(fp);
	b=getc(fp);
	if((a!='P')||(b!='K'))
	{
		printf("No .zip file: '%s'\n",name);
		fpurge(fo);
		return;
	}
	s=filsiz-1;
	for(;;)
	{
		if(s<0)
		{
			printf("Zip file ????: '%s'\n",name);
			fpurge(fo);
			return;
		}
		if(lsrc(s)) break;
		s--;
	}
	printf("Inserting...\n");
	fseek(fp,0L,0);
	fseek(fo,0L,0);
	aa=posi;
	bb=0L;
	blk=0;
	for(;aa>0x100000;)
	{
		if($readw(fp->io_lun,buj,4096,blk)!=4096)
		{
			printf("Read error: '%s'\n",name);
			fpurge(fo);
			return;
		}
		if($writw(fo->io_lun,buj,4096,blk)!=4096)
		{
			printf("Write error: '%s'\n",name);
			fpurge(fo);
			return;
		}
		blk+=16;
		aa-=0x100000;
		bb+=0x100000;
	}
	fseek(fp,bb,0);
	fseek(fo,bb,0);
	a=((int *)&aa)[0];
	a<<=9;
	a+=((int *)&aa)[1];
	if(a)
	{
		if(fread(buj,1,a,fp)!=a)
		{
			printf("Read error: '%s'\n",name);
			fpurge(fo);
			return;
		}
		if(fwrite(buj,1,a,fo)!=a)
		{
			printf("Write error: '%s'\n",name);
			fpurge(fo);
			return;
		}
	}
	putc(blen&0377,fo);
	putc((blen>>8)&0377,fo);
	if(fwrite(buc,1,blen,fo)!=blen)
	{
		printf("Can't write banner.\n");
		fpurge(fo);
		return;
	}
	fclose(fo);
}

extern long (ftell)();

lsrc(s)
int s;
{
	int i,a,b,c,d,e;
	e=(s==(filsiz-1))?500:509;
	((int *)&posi)[0]=s;
	((int *)&posi)[1]=0;
	fseek(fp,posi,0);
	b=getc(fp);
	c=getc(fp);
	d=getc(fp);
	for(i=0;i<e;i++)
	{
		a=b;
		b=c;
		c=d;
		d=getc(fp);
		if((a=='P')&&(b=='K')&&(c==5)&&(d==6))
		{
			for(i=0;i<16;i++)
				a=getc(fp);
			posi=ftell(fp);
			return 1;
		}
	}
	return 0;
}


static FILE *fd;
static char wname[100];
static int cat[512],seg,*ptr;
static long pos;

drOpen(dirname)
char *dirname;
{
	char *p,*q;
	/* Take device name */
	for(p=dirname,q=wname;;q++,p++)
	{
		if((*q=(*p))=='\0') {*q=':';break;}
		if(*q==':') break;
	}
	q[1]='\0';
	/* Open device like a file */
	fd=fopen(wname,"rnd");
	if(fd==0) return 0;
	ptr=cat;
	cat[0]=04000;
	cat[1]=1;			/* First segment */
	return 1;
}

char *drNext()
{
	int i;
	for(;;)
	{
		while((ptr[0]&0177400)==04000)
		{
			if((seg=cat[1])==0)
			{
				fclose(fd);
				return 0;
			}
			pos=seg+2;
			pos<<=17;
			fseek(fd,pos,0);
			if(fread(cat,2,512,fd)!=512)
			{
				fclose(fd);
				return(0);
			}
			ptr=cat+5;
		}
		if(((ptr[0]&0177400)==02000)&&(ptr[3]!=RAD50(B,A,D))) break;
		ptr+=7+cat[3]/2;
	}
	r50toa(wname, ptr+1, 2);
	r50toa(wname+7, ptr+3,1);
	wname[6]='.';
	wname[10]='\0';
	filsiz=ptr[4];
	ptr+=7+cat[3]/2;
	return(wname);
}

patmat(raw,pat)
char *raw,*pat;
{
	int  i ;
	if(*pat=='\0') return (*raw=='\0');
	if(*pat=='*')
	{
		if(*(pat+1)=='\0')	return( 1 ) ;
		for(i=0;i<=strlen(raw);i++)
			if((*(raw+i)==*(pat+1)) ||
			 (*(pat+1)=='?') || (*(pat+1)=='%'))
				if(patmat(raw+i+1,pat+2) == 1) return(1);
	}
	else
	{
		if(*raw=='\0') return 0;
		if((*pat=='%')||(*pat=='?')||(*pat == *raw))
			if(patmat(raw+1,pat+1)==1) return 1;
	}
	return 0;
}

static char jname[100];
char *trim(str)
char *str;
{
	char *p;
	for(p=jname;*str;str++) if((*p=(*str))!=' ') p++;
	*p='\0';
	return jname;
}

#include	<ctype.h>

stos(a,b)
char *a,*b;
{
	for(;*b++=(*a++););
}

ustos(a,b)
char *a,*b;
{
	for(;*b++=toupper(*a++););
}

static int state;
static char dname[10];

dvOpen(dn)
char *dn;
{
	state=0;
	if(*dn=='*') dn="DK*";
	stos(dn,dname);
	if(*dn=='\0') {stos("DK",dname);return;}
	if(((dn[2]>='0')&&(dn[2]<='7'))||(dn[2]!='*')) return;
	state='0';
}

char *dvNext()
{
	if(state=='8') return 0;
	if(state==0) { state='8';return(dname);}
	dname[2]=state++;
	return(dname);
}

parnam(d,f,s)
char *d,*f,*s;
{
	char *p;
	int fld=0,fldd=0;
	for(p=s;*p;p++) if(*p=='.')fld++;else if(*p==':')fldd++;
	if(fldd)
	{
		for(p=s;*p!=':';*d++=(*p++));
		*d='\0';
		p++;
		if(*p=='\0') { stos("*.ZIP",f);return;}
	}
	else
	{
		stos("DK",d);p=s;
	}
	if(*p=='.') *f++='*';
	do{*f++=_toupper(*p);}while(*p++);
	if(fld==0) { *(f-1)='.';*f++='Z';*f++='I';*f++='P';*f='\0';}
}

buildname(a,b,c)
char *a,*b,*c;
{
	for(;;)
	{
		*c=(*a++);
		if((*c=='\0')||(*c==':')) break;
		c++;
	}
	*c++=':';
	stos(b,c);
}

strdup(ptr)
{
	int retcode;
	if(retcode=malloc(strlen(ptr)+1)) stos(ptr,retcode);
	return(retcode);
}
                                                                                                                                                                                                                                                                                                                                               