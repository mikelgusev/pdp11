/*	��������� UBLIST -> ZXGold	*/
#include	<stdio.h>
#include <rad50.h>
FILE	*fi,*fo,*fd;
char	rname[8],name[20],a[40],b[40],c[40],d[40];
int	cat[512];

main(n,v)
int	n;
char	*v[];
{
	int seg,pos,*ptr,i;
	if(n==1)
	{
		printf("CONVERTOR FROM UBLIST 2 'PHONES.ZXG'\n");
		printf("Use like: 'file.ubt' or '*' for first .UBT file\n");
		exit(1);
	}
	fo=fopen("phones.zxg","w");
	if(*v[1]!='*')
	{
		if(frp1(name,v[1],"dk:",".ubt","\0","dk:ublist.ubt"))
			error("????? bad file name '%s'",v[1]);
		fi=fopen(name,"r");
		if(fi==0)	error("????? File '%s' not found",v[1]);
		onefile();
		exit(1);
	}
	/* Find first .UBT file */
	fd=fopen("dk:","rnd");
	if(fd==0)	error("????? DK: directory open error\n");
	seg=1;
	do
	{
		pos=seg+2;
		pos<<=17;
		fseek(fd,pos,0);
		if(fread(cat,2,512,fd)!=512)	error("????? Reading error\n");
		for(ptr=cat+5;(ptr[0]&0177400)!=04000;ptr+=7+cat[3]/2)
		if(((ptr[0]&0177400)==02000)&&(ptr[3]==RAD50(U,B,T)))
		{
			r50toa(rname, ptr+1, 2);
			i=6;do{rname[i]='\0';}while(rname[--i]==' ');
			printf("%s\n",rname);
			if(!frp1(name,rname,"dk:",".ubt","\0","dk:ublist.ubt"))
			{
			    fi=fopen(name,"r");
			    if(fi==0) printf("????? '%s' not found",name);
			    else onefile();
			    exit(1);
			} else printf("????? bad frp1 for '%s'",rname);
		}
	} while(seg=cat[1]);
	printf("????? File *.UBT not found");
	fclose(fd);
}

onefile()
{
	char i;
	int j,total;
	total=0;
	for(;;)
	{
		do{i=getc(fi);}while(i!='�');
		do{i=getc(fi);}while(i!=' ');
		for(j=0;j<6;j++) a[j]=getc(fi);a[j]='\0';
		if(streq(a,"Moscow")) 
		{
			printf("City '%s'\n",a);
			do{i=getc(fi);}while(i!='\n');
			for(;;)
			{
				do{i=getc(fi);}while(i!='\n');
				i=getc(fi);i=getc(fi);
				if(i=='�') break;
				for(j=0;;j++)
				{
					i=getc(fi);
					if(i=='�') break;
					a[j]=i;
				}
				do{a[j]='\0';}while(a[--j]==' ');
				for(j=0;;j++)
				{
					i=getc(fi);
					if(i=='�') break;
					b[j]=i;
				}
				b[j]='\0';
				do{i=getc(fi);}while(i!='�');
				i=getc(fi);
				for(j=0;;j++)
				{
					i=getc(fi);
					if(i=='�') break;
					c[j]=i;
				}
				do{c[j]='\0';}while(c[--j]==' ');
				i=getc(fi);
				for(j=0;;j++)
				{
					i=getc(fi);
					if(i=='�') break;
					d[j]=i;
				}
				do{d[j]='\0';}while(d[--j]==' ');
				if(!streq(b," -mail--only- ")&&!streq(b," -temp-down-- "))
					fprint(fo,"%s {%s} <%s> [%s]\n",b,a,c,d);
				printf("%d\r",++total);
			}
			printf("\n");
			break;
		}
		else
		{
			printf("Drop city: '%s'\n",a);
		}
	}
	fclose(fi);
	fclose(fo);
}

                                                                                                                                                                                                                                                                                                                                                                                                                                                                      