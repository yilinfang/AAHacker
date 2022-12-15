
ALL: clean aa_server

.PHONY: clean
clean:
	rm -f aa_server

aa_server:
	rm -f aa_server
	g++ ./main.cpp ./Message.cpp ./utils.cpp -lssl -lcrypto  -O0 -g -o aa_server