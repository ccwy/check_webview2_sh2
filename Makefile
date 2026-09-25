# Makefile for check_env.exe (GUI版本)
# 使用MinGW-w64静态链接编译

CC = gcc
CFLAGS = -Wall -O2 -DUNICODE -D_UNICODE
LDFLAGS = -static

TARGET = check_env.exe
SRC = check_env.c
RES_OBJ = resource.o
LIBS = -ladvapi32 -lversion -lshell32 -lcomctl32

.PHONY: all clean

all: $(TARGET)

$(RES_OBJ): resource.rc app.manifest
	windres resource.rc -o $(RES_OBJ)

$(TARGET): $(SRC) $(RES_OBJ)
	$(CC) $(SRC) $(RES_OBJ) -o $(TARGET) $(CFLAGS) $(LDFLAGS) -mwindows $(LIBS)

clean:
	del /f $(TARGET) $(RES_OBJ) 2>nul || rm -f $(TARGET) $(RES_OBJ)