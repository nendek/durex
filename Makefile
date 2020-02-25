all:
	make -f ./Makefile.Client
	make -f ./Makefile.Payload

Client:
	make -f ./Makefile.Client

Payload:
	make -f ./Makefile.Payload

clean:
	make clean -f ./Makefile.Client
	make clean -f ./Makefile.Payload

fclean:
	make fclean -f ./Makefile.Client
	make fclean -f ./Makefile.Payload

re: clean all
