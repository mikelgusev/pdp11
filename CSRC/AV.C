#include	<stdio.h>

FILE *of;

char dvnam[20],flnam[20];
extern char name[40];
char name[40];

int asterix=0,altgost=0,overwrite=0,donotshow=0,flscan=0,flist=0;

int type;

main(n,a)
char *a[];
{
	int np;
	char *dp,*df,*kp,*nap;
	if(n==1)
	{
		fprintf(stderr,"(C) Miha Gusew 1994, ArcViewer, ZIP,ARJ,LZH,LZS\n");
		fprintf(stderr,"Use like:\n>[-keys] pattern pa...\n");
		fprintf(stderr,"keys is -n - don't show header (for unarc)\n");
		fprintf(stderr,"        -o - overwrite existing files (for unarc)\n");
		fprintf(stderr,"        -g - alt -> gost (for unarc)\n");
		fprintf(stderr,"	-l - only show catalog\n");
		fprintf(stderr,"        -* - without selecting\n");
		fprintf(stderr,"        -& - show all scanning files\n");
		fprintf(stderr,"pattern is dev:fil.ext\n");
		fprintf(stderr,"        dev - [],[FD:],[HD*:]\n");
		fprintf(stderr,"        fil - [],[*..?..%%]\n");
		fprintf(stderr,"        ext - [],[*..?..%%]\n");
		exit(1);
	}
	for(np=1;np<n;np++)
		if(*(kp=a[np])=='-')
			for(;*kp;kp++)
				switch(*kp)
				{
				case '-': break;
				case 'n':
				case 'N': donotshow++;break;
				case 'o':
				case 'O': overwrite++;break;
				case 'g':
				case 'G': altgost++;break;
				case '*': asterix++;break;
				case '&': flscan++;break;
				case 'l':
				case 'L': flist++;break;
				default:fprintf(stderr,"Key '%c' ignored\n",*kp);
				}
	if(!flist)
	{
		of=fopen("avvvvv.tmp","w");
		if(!of)
		{
			fprintf(stderr,"Can't create [avvvvv.tmp] command file\n");
			exit(1);
		}
	}
	rcopen();
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
						if(flscan) printf("%s %s\n",df,trim(df));
						buildname(dp,trim(df),name);
						if(type=aropen(name))
						{
							printf("Dev: [%s] Arc: [%s]\n",dp,name);
							if(asterix)
							{
								takeall(type,name);
								arclose();
							}
							else
							{
								if(!flist) rcarchive(name);
								while(nap=arnext())
								{
									if(flist)
										printf("Dev: [%s] Arc: [%s] File: [%s]\n",dp,name,nap);
									else
										rcfile(nap,type);
								}
							}
						}
					}
				}
				else
					printf("#device [%s] open error\n",dp);
			}
		}
	}
	if(asterix)
	{
		fprintf(of,"del avvvvv.tmp\n");
		fclose(of);
		system("@avvvvv.tmp",12);
		exit(1);
	}
	if(flist)
		exit(1);
	if(rclist())
	{
		fprintf(of,"del avvvvv.tmp\n");
		fclose(of);
		system("@avvvvv.tmp",12);
		exit(1);
	}
	else
		fpurge(of);
}
                                                                                                                                                                                                                                                                                                                                     