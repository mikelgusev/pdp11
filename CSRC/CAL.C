#include	<stdio.h>

int	crc=0;

updcrc(data)
int data;
{	int	i,carry;
	for(i=0;i<8;i++)
	{
		carry=crc & 0x8000;
		crc<<=1;
		if(data&0x80) crc|=1;
		if(carry) crc^=0x1021;
		data<<=1;
	}
}

main()
{
	int	first,cur;
	printf("Taking file from STDIN,First symbol is the last symbol\n");
	first=getchar();
	printf("Symbol (hex) = %02x\n",first);
	while(first!=(cur=getchar()))
	{
	 if((cur!=015)&&(cur!=012))
		{
		 updcrc(cur);
		 printf("Symbol: %c %0x   CRC is %04x\n",cur,cur,crc);
	 	}
	}
	updcrc(0);
	printf("Symbol: 0 0   CRC is %04x\n",crc);
	updcrc(0);
	printf("Symbol: 0 0   CRC is %04x\n",crc);
}

                                                                                                                                                                                                                                                                                                                                                                                             