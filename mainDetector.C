#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <ctype.h>

int main() {
    int serial_fd;
    struct termios tty;
    FILE * file;
    struct stat st;
    long last_size, current_size;
    char *buffer;
    char *lower_buffer;
    long bytes_to_read;
    int i;

    //open the serial port
    serial_fd = open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_SYNC);

    // Configure serial port
    tcgetattr(serial_fd, &tty);
    cfsetospeed(&tty, B9600);
    cfsetisspeed(&tty, B9600);
    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
    tty.c_iflag &= ~IGNBRK;
    tty.c_lflag = 0;
    tty.c_oflag = 0;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 10;
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~(PARENB | PARODD);
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CRTSCTS;
    tcsetattr(serial_fd, TCSANOW, &tty);
}