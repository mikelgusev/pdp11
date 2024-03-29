/* ArcViewer library */
/* int drOpen(char *dirname);		= 0 or 1	*/
/* char *drNext();			= 0 or ptr	*/

#include	<stdio.h>
#include	<rad50.h>

static FILE *fd;
static char name[100];
static int cat[512],seg,*ptr;
static long pos;

drOpen(dirname)
char *dirname;
{
	char *p,*q;
	/* Take device name */
	for(p=dirname,q=name;;q++,p++)
	{
		if((*q=(*p))=='\0') {*q=':';break;}
		if(*q==':') break;
	}
	q[1]='\0';
	/* Open device like a file */
	fd=fopen(name,"rnd");
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
	r50toa(name, ptr+1, 2);
	r50toa(name+7, ptr+3,1);
	name[6]='.';
	name[10]='\0';
	ptr+=7+cat[3]/2;
	return(name);
}

                                                                                                                                                                                                                                                                                                                                                                                                                                                      