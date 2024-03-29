#include <stdio.h>
#define	ex exp()

FILE *in,*outp,*outn;
struct fboss
{
	long bpos,fpos;
	unsigned zone,net,node;
} master;

struct fpoint
{
	long ppos;
	unsigned point;
} slave;

main(n,v)
char *v[];
{
	int zone,net,node,point,i;
	char *s;
	s=malloc(200);
	if(n!=2)
	{
		printf("(C) Miha Gusew, Point list translator\n");
		printf("Use like:\n");
		printf("pnt> pntxxx.ndl\n");
		printf("--> 'points.idx'\n");
		printf("--> 'nodes.idx'\n");
		exit(1);
	}
	in=fopen(v[1],"r");
	if(!in)
	{
		printf("File '%s' not found\n",v[1]);
		exit(1);
	}
	outp=fopen("points.idx","wn");
	if(!outp)
	{
		printf("Bad file 'points.idx' creation\n");
		exit(1);
	}
	outn=fopen("nodes.idx","wn");
	if(!outn)
	{
		printf("Bad file 'nodes.idx' creation\n");
		fpurge(outp);
		exit(1);
	}
	zone=(-1);
	for(;;)
	{
		slave.ppos=(master.bpos=ftell(in));
		if(fgetss(s,200,in)==0) if(ferror(in))
		{
			printf("Error reading..\n");
			ex;
		} else break;
		if(s[0]!=0 && s[0]!=';')
		{
			if(s[0]=='B')
			{
				i=sscanf(s,"Boss,%d:%d/%d,",
					&master.zone,&master.net,&master.node);
				if(i!=3)
				{
					printf("Bad input string '%s', halt.\n",s);
					ex;
				}
				slave.ppos=(-1L);
				i=fwrite(&slave,1,sizeof(struct fpoint),outp);
				if(i!=sizeof(struct fpoint))
				{
					printf("Write error to 'points.idx' %d\n",$$ferr);
					ex;
				}
				master.fpos=ftell(outp);
				i=fwrite(&master,1,sizeof(struct fboss),outn);
				if(i!=sizeof(struct fboss))
				{
					printf("Write error to 'nodes.idx' %d\n",$$ferr);
					ex;
				}
			}
			else
			if(s[0]=='P')
			{
				i=sscanf(s,"Point,%d,",&slave.point);
				if(i!=1)
				{
					printf("Illegal string '%s'\n",s);
					ex;
				}
				i=fwrite(&slave,1,sizeof(struct fpoint),outp);
				if(i!=sizeof(struct fpoint))
				{
					printf("Write error to 'points.idx' %d\n",$$ferr);
					ex;
				}
			}
			else
				printf("Input string '%s' ignored\n",s);
		}
	}
	fclose(in);
	fclose(outp);
	fclose(outn);
}

exp()
{
	fpurge(outp);
	fpurge(outn);
	exit(1);
}
                                                                                                                                                                                                                                                                                                                                                                                                                                                                     