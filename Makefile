all:
	make -f ./Makefile.Client
	make -f ./Makefile.Durex

Client:
	make -f ./Makefile.Client

Durex:
	make -f ./Makefile.Durex

clean:
	make clean -f ./Makefile.Client
	make clean -f ./Makefile.Durex

fclean:
	make fclean -f ./Makefile.Client
	make fclean -f ./Makefile.Durex

re: clean all
