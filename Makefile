CXX = gcc
#CP = cp
CXXFLAGS = -L. -Iinclude -lpthread -lcrypto -lssl -lxml2 -lm
TARGET = agent_main
OBJS = main.o thread_pool.o cryptdatafunc.o ini_config.o
CFLAGS = -g -c
#STATICLIB = libssl.a libcrypto.a libxml2.a
#LKFLAGS =
#INSTALLDIR = /mnt/
#install:
#	$(CP) $(TARGET) $(INSTALLDIR)

all:$(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ $(CXXFLAGS) 

main.o: main.c thread_pool.c ini_config.c
	$(CXX) $(CFLAGS) $^ 
thread_pool.o: thread_pool.c cryptdatafunc.c ini_config.c
	$(CXX) $(CFLAGS) $^ 
cryptdatafunc.o: cryptdatafunc.c
	$(CXX) $(CFLAGS) $^ 
ini_config.o: ini_config.c
	$(CXX) $(CFLAGS) $^ 
clean:
	@echo "cleaning project"
	-rm main*.o thread_pool*.o cryptdatafunc*.o ini_config*.o
	@echo "clean completed"
.PHONY: clean
