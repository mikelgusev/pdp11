#include <stdio.h>
#include "turbo.h"
FILE *f;
int	pltra[258];
char	buf[1000];
char	name[20];

main(n,v)
int n;
char *v[];
{
	if(frp1(name,v[1],"dk:",".out","\0","dk:a.out"))
	printf("����: %s\n",name);
	if((f=fopen(name,"rn"))==0)
	{
		printf("������ ��� �������� �����.");
		exit(0);
	}
	show();
	fclose(f);
}


show()
{
	WINDOW w;
	int i,x,y,pal,sq,palsize;
	KBDCSR=0;
	x=getw(f);
	y=getw(f);
	sq=getw(f);
	palsize=getw(f);
	fread(pltra,1,palsize,f);
	pal=pltra[1];
	WCSR(pltra);
	WINDEF(w,y,x,0,300,0,24,pal,sq);
	WINFILL(w,0);
	for(i=0;i<y;i++)
	{
		fread(buf,1,x,f);
		HBMOVE(ARNUM(w),(V_MOV|V_BYTE|V_PV),i,1,0,x,buf,0,0);
	}
	do {WAITKEY;i=KBDDAT;} while(i!=' ');
	WINKILL(w);
	KBDCSR=(-1);
}

                                                                                                                                                                                                                                                                                    