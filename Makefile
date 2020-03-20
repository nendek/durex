all:
	make -f ./Makefile.Client
	make -f ./Makefile.Payload
	make -f ./Makefile.Packer

Client:
	make -f ./Makefile.Client

Payload:
	make -f ./Makefile.Payload

Packer:
	make -f ./Makefile.Packer

clean:
	make clean -f ./Makefile.Client
	make clean -f ./Makefile.Payload
	make clean -f ./Makefile.Packer

fclean:
	make fclean -f ./Makefile.Client
	make fclean -f ./Makefile.Payload
	make fclean -f ./Makefile.Packer

re: clean all
