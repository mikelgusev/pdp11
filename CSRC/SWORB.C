static int mfhlt[]={ 012737 , 0 , 0174220 , 0240 , 0207 };
typedef (* funptr)();
#define	MFHLT(a)	(mfhlt[1]=a,(*((funptr)mfhlt))())

main()
{
	unsigned int reg,lreg,desreg,stat,proc,name[9];
	printf("register descriptor procedure  fl  name\n");
	for(reg=0170000;reg!=0;reg+=2) {
		lreg=(reg&07777)|0150000;
		desreg=MFHLT(lreg);
		if(desreg) {
			stat=MFHLT((desreg+4));
			proc=MFHLT((desreg+6));
			printf("  %6o     %6o    %6o  ",reg,desreg,proc);
			printf("%c%c  ",stat&04000?'r':'.',stat&02000?'w':'.');
			if((stat&0400)||(proc<0100000)) {
				printf("<halt>\n");
			} else if(proc<0140000){ int i;
				proc+=060;
				for(i=0;i<8;i++) {
					name[i]=MFHLT(proc);
					proc+=2;
				}
				name[8]=0;
				printf("%s\n",name);
			} else printf("<bad>\n");
		}
	}
}
                                                                                                                                                                                                                                  