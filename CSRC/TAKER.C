/***************************************************************************
 Format:		
	x	2	������ �� x
	y	2	������ �� y
	sq	2	�������� ������
	palsize	2	������ ������� � ���������� � ������ (36/516)
	palet	36/516	������� � ����������, ������� � ���������
	data	...	������
***************************************************************************/


#include <stdio.h>
#include "turbo.h"

FILE	*f;

int mview=0,view,area,areax,areay,aream,regim,palette,colors,palsize,sq;
int x,y,ax,ay;
int pltra[258];	/* For palette */
char buf[1000]; /* For Pixels */
char name[20],oname[20];

main(n,v)
int n;
char *v[];
{
	int i,key;
	KBDCSR=0;
	printf("(c) 1994 Miha Gusew *** ����������� �������� ***\n");
	oname[0]='\0';
	if(n==1)
	{
		printf("-i[file][.out]  - ��������� ����\n");
		printf("-o[file][.out]  - �������� � ����\n");
		printf("�� ���������:\n");
		printf("1. ������ �� �����������\n");
		printf("2. ������� ����� ���������� �� 'a.out'\n");
		exit(0);
	}
	for(i=1;i<n;i++)
	{
		if(v[i][0]!='-')
		{
			printf("What is this?? %s\n",v[i]);
			exit(0);
		}
		switch(v[i][1])
		{
			case 'i':
			case 'I':	load(&v[i][2]);
					break;
			case 'o':
			case 'O':	frp1(oname,&v[i][2],"dk:",".out","[-1]","dk:a.out[-1]");
					printf("�������� ����: %s\n",oname);
					break;
			default:	printf("What is this?? %s\n",v[i]);
					exit(0);
		}
	}

	VWLOOK(0);
	mview=a[1];
	if(rotate()) exit(0);
	take();
	for(;;)
	{
		printf("Main: Rot,Take,Acor,Bcor,Out\n");
		WAITKEY;key=KBDDAT;
		switch(key&0137)
		{
			case '\3':	exit(0);
					break;
			case 'R':	if(!rotate()) take();
					break;
			case 'T':	take();
					break;
			case 'A':	ach();
					break;
			case 'B':	bch();
					break;
			case 'O':	out();
					break;
		}
	}
}


wrapup()
{
	if(mview) normal();
	KBDCSR=255;
	printf("����� ������. ������� �������� �� �������.\n");
}


load(str)
char *str;
{
	frp1(name,str,"dk:",".out","\0","dk:a.out");
	printf("������� ����: %s\n",name);
	if((f=fopen(name,"rn"))==0)
		printf("������ ��� �������� �����.");
	else
		show();
	fclose(f);
}


show()
{
	WINDOW w;
	int i,x,y,pal,sq,palsize;
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
}


rotate()
{	int key;
	printf("������� ����: <������>, ���������� �����: <����>.\n");
	for(;;)
	{
		a[1]=0;
		do
		{
			view=a[1];
			VWLOOK(view);
		} while (a[1]);
		VWFORE(view);
		for(;;)
		{
			WAITKEY;key=KBDDAT;
			if(key==' ') break;
			if(key=='\15') {return 0;}
			if(key=='\3') {return 1;}
		}
	}
}


normal()
{
	do {
		a[1]=0;
		do
		{
			view=a[1];
			VWLOOK(view);
		} while (a[1]);
		VWFORE(view);
	} while(view!=mview);
}


take()
{
	static int arcolor[5]={2,4,16,16,256};
	static int plength[5]={36,36,36,36,516};
	int ur;
	VWTAKE(view);
	area=a[2];
	sq=a[9];
	takeinfo(area);
	aream&=0140007;
	regim=aream&7;
	palette=aream&0140000>>14;
	if (regim>3 && regim<7)
	{
		regim&=3;
		palette|=4;
	}
	if(regim==7) regim=4;
	colors=arcolor[regim];
	palsize=plength[regim];
	printf("area=%u  view=%u\n",area,view);
	printf("x=%u  lins=%u  vmpl=%u\n",areax,areay,aream);
	printf("colors=%u  palette=%u\n",colors,palette);
	printf("taking palette ... ");
	pltra[0]=21;
	pltra[1]=aream;
	WCSR(pltra);
	printf("OK\n");
}

ach()
{	int key;
	printf("����� ������� ����� �����.\n");
	x=0;
	y=0;
	for(;;)
	{
		HBMOVE(area,(V_XOR|V_BYTE|V_CV),y,2,x,2,0252,0,0);
		do { WAITKEY;key=KBDDAT;} while(key==27 || key=='[');
		HBMOVE(area,(V_XOR|V_BYTE|V_CV),y,2,x,2,0252,0,0);
		switch(key)
		{
		case 65: if(y) y--;break;
		case 68: if(x) x--;break;
		case 66: if(y!=areay-1) y++;break;
		case 67: if(x!=areax-1) x++;break;
		case 32: return 1;break;
		case 13: return 0;break;
		}
	}
}


bxor()
{
	HBMOVE(area,(V_XOR|V_BYTE|V_CV),y,1,x,ax,0252,0,0);
	if(ay!=1)
	{
	HBMOVE(area,(V_XOR|V_BYTE|V_CV),(y+ay-1),1,x,ax,0252,0,0);
	if(ay>=3)
	{
	HBMOVE(area,(V_XOR|V_BYTE|V_CV),(y+1),(ay-2),x,1,0252,0,0);
	HBMOVE(area,(V_XOR|V_BYTE|V_CV),(y+1),(ay-2),(x+ax-1),1,0252,0,0);
	}
	}
}


bch()
{	int key;
	printf("����� ������ ������ �����.\n");
	ax=1;
	ay=1;
	for(;;)
	{
		bxor();
		do { WAITKEY;key=KBDDAT;} while(key==27 || key=='[');
		bxor();
		switch(key)
		{
		case 65: if(ay!=1) ay--;break;
		case 68: if(ax!=1) ax--;break;
		case 66: if(ay+y!=areay) ay++;break;
		case 67: if(ax+x!=areax) ax++;break;
		case 32: return 1;break;
		case 13: return 0;break;
		}
	}
}


badfil()
{
	printf("������ ������ � ����\n");
	exit(0);
}


out()
{
	int i;
	normal();
	if((f=fopen(oname,"wn"))==0)
	{
		printf("������ ��� �������� ��������� �����.\n");
		exit(0);
	}
	putw(ax,f);
	putw(ay,f);
	putw(sq,f);
	putw(palsize,f);
	pltra[0]=19;
	if(fwrite(pltra,1,palsize,f)!=palsize) badfil();
	for(i=0;i<ay;i++)
	{
		msg(i%40?".\200":".");
		HBMOVE(area,(V_MOV|V_BYTE|V_VP),(y+i),1,x,ax,buf,0,0);
		if(fwrite(buf,1,ax,f)!=ax) badfil();
	}
	fclose(f);
	printf("\n������� �������� ����.\n");
}
                                                                                                                                                                                                                                                                                                                                            