# Makefile for check_env.exe
# 使用MinGW-w64静态链接编译

CC = gcc
CFLAGS = -Wall -O2 -DUNICODE -D_UNICODE
LDFLAGS = -static -ladvapi32 -lversion

TARGET = check_env.exe
SRC = check_env.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(SRC) -o $(TARGET) $(CFLAGS) $(LDFLAGS)

clean:
	del /f $(TARGET) 2>nul || rm -f $(TARGET)