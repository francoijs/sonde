INC		= -I. -I/usr/include/wireshark -I/usr/include/wireshark/wiretap `pkg-config --cflags glib-2.0`
LIBS	= -lwireshark -lwsutil -lwiretap -lpcap `pkg-config --libs glib-2.0`
CFLAGS	= -Wall -g

SOURCE 	= sonde.cpp		\
#		  cfile.c

all:
	gcc $(CFLAGS) $(INC) $(SOURCE) $(LIBS) -o sonde
