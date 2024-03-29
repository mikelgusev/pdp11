/* ArcViewer library */

#include <stdio.h>
extern of,altgost,donotshow,overwrite,asterix;
extern char *arc[];
char *arc[]={"ZE","AE","LE","UZ",0};


takeall(at,name)
int at;
char *name;
{
	if((at>=1)&&(at<=4))
	{
		fprintf(of,"%s %s",arc[at-1],name);
		inskey(at);
		fprintf(of,"\n");
	}
	else
		fprintf(stderr,"error in program logic, take all from not 1..3\n");
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


inskey(at)
int at;
{
	if((at!=4)&&altgost) fprintf(of,"/g");
	if(overwrite) fprintf(of,"/o");
	if((at!=4)&&donotshow) fprintf(of,"/n");
}

                                                                                                                                                                                                                                                                                                                                                    