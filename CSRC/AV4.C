/* ArcViewer library */

#include <stdio.h>
#define ofs(a) (*((int*)(header+a)))
#define off {fclose(file);return 0;}

static FILE *file;
static char header[1000];
static int artype;
static long ptr,aaa,bbb,ccc;

aropen(name)
{
	ptr=0L;
	if(file=fopen(name,"rn"))
	{
		if(fread(header,1,8,file)!=8) off;
		if((ofs(0)==045520)&&(ofs(2)==02003)) return artype=1;
		if(ofs(0)==0xEA60)
		{
			ptr=(long)(ofs(2)+10L);
			return artype=2;
		}
		if((header[2]=='-')&&(header[3]=='l')&&(header[6]=='-'))
			return artype=3;
		if(ofs(0)==047443)
		{
			ptr=16L;
			return artype=4;
		}
		off;
	}
	return 0;
}

arnext()
{
	int j;
	avseek(file,ptr);
	switch(artype)
	{
	case 1:	
		if(fread(header,1,30,file)!=30) off;
		if((ofs(0)!=045520)||(ofs(2)!=02003)) off;
		j=ofs(26)+ofs(28);
		if(fread(header+30,1,j,file)!=j) off;
		header[30+ofs(26)]='\0';
		aaa=(unsigned int)(01000-file->io_bcnt);
		bbb=((long)(file->io_bnbr-1))<<9;
		((int*)(&ccc))[1]=ofs(18);
		((int*)(&ccc))[0]=ofs(20);
		ptr=aaa+bbb+ccc;
		return(header+30);
		break;
	case 2:	
		if(fread(header,1,2,file)!=2) off;
		if(ofs(0)!=0165140) off;
		if(fread(header,1,2,file)!=2) off;
		if((j=ofs(0))==0) off;
		if(fread(header,1,j+6,file)!=j+6) off;
		aaa=(unsigned int)(01000-file->io_bcnt);
		bbb=((long)(file->io_bnbr-1))<<9;
		((int*)(&ccc))[1]=ofs(12);
		((int*)(&ccc))[0]=ofs(14);
		ptr=aaa+bbb+ccc;
		return(header+30);
		break;
	case 3:
		j=getc(file)&0xFF;
		if(j==0) off;
		if(fread(header,1,j+1,file)!=j+1) off;
		if((header[1]!='-')||(header[2]!='l')||(header[5]!='-')) off;
		aaa=(unsigned int)(01000-file->io_bcnt);
		bbb=((long)(file->io_bnbr-1))<<9;
		((int*)(&ccc))[1]=ofs(6);
		((int*)(&ccc))[0]=ofs(8);
		ptr=aaa+bbb+ccc;
		header[025+header[024]]='\0';
		return(header+025);
		break;
	case 4:	if(fread(header,1,16,file)!=16) off;
		if(ofs(0)==0) off;
		aaa=(unsigned int)(01000-file->io_bcnt);
		bbb=((long)(file->io_bnbr-1))<<9;
		((int*)(&ccc))[1]=ofs(12)+ofs(12)&1;
		((int*)(&ccc))[0]=ofs(14);
		ptr=aaa+bbb+ccc;
		r50toa(header+6,header,2);
		for(j=12;header[j-1]==' ';j--);
		header[j++]='.';
		r50toa(header+j,header+4,1);
		for(j=j+3;header[j-1]==' ';j--);
		header[j]='\0';
		return(header+6);
		break;
	default:printf("FUCK U\n");
	}
}

arclose()
{
	fclose(file);
}


avseek(file,ptr)
long ptr;
FILE *file;
{
	long a;
	a=(ptr&0x1FF)|(ptr&(~0x1FF))<<7;
	fseek(file,a,0);
}

                                                                                          