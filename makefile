CC = gcc
HEADERS = include/
SRC = src/
FLAGS = -Wall -ansi -pedantic
PROGRAM = my_sniffer

$(PROGRAM): $(SRC)* $(HEADERS)*
	$(CC) $(SRC)* -I $(HEADERS) -o $(PROGRAM) $(FLAGS)

clean:
	rm $(PROGRAM)
