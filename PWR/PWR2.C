about()
{
		printf("(C) Miha Gusew, Packet WRiter for Mailer\n");
		printf("pwr> [&][^][#]filein[.lst]\n");
		printf("   & - show work (debug)\n");
		printf("   ^ - insert ^Afmpt & ^Atopt anyway\n");
		printf("   # - make special last message\n");
		printf("Syntaxis of filein.lst:\n");;
		printf("packet     nn:nn/nn[.nn] nn:nn/nn[.nn]\n");
		printf("secret_password\n");
		printf("[tearline  default tearline]\n");
		printf("[origin    default origin]\n");
		printf("[fromname  default from name]\n");
		printf("[toname    default to name]\n");
		printf("[defarea   default area]\n");
		printf("[defmessag nn/nn[.nn] nn/nn[.nn]\n\n");
		printf("[messag nn/nn[.nn] nn/nn[.nn]]\n");
		printf("[dest   nn/nn[.nn]\n");
		printf("[from   name-from]\n");
		printf("[to     name-to]\n");
		printf("subj   subject\n");
		printf("[area   area-name]\n");
		printf("[reply reply code]\n");
		printf("[noinfo]\n");
		printf("^B message ^B\n");
		exit(1);
}

off()
{
	printf("Write error\n");
	exit(1);
}



stos(a,b)
char *a,*b;
{
	for(;*b++=(*a++););
}

                                                                                                                                                                                                                                                                                                                                                                                                                                                                 