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

    // open the serial port
    serial_fd = open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_SYNC);

    // configure serial port
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

    sleep(2);

    // get file size
    stat("/var/log/snort/alerts", &st);
    last_size = st.st_size;

    write(serial_fd, "A", 1);

    while (1) {

        //get current file size
        stat("/var/log/snort/alerts", &st);
        current_size = st.st_size;

        if (current_size > last_size) {
            //open file and seek to last position
            file = fopen("/var/log/snort/alerts", "r");
            fseek(file, last_size, SEEK_SET);

            // read new data
            bytes_to_read = current_size - last_size;
            buffer = malloc(bytes_to_read + 1);
            fread(buffer, 1, bytes_to_read, file);
            buffer[bytes_to_read] = '\0';
            fclose(file);

            // convert to lowercase
            lower_buffer = malloc(bytes_to_read + 1);
            for (i = 0, i <= bytes_to_read; i++) {
                lower_buffer[i] = tolower(buffer[i]);
            }

            // check for alerts

            // check for icmp
            if (strstr(lower_buffer, "icmp")) {
                printf("ICMP Alert\n");
                write(serial_fd, "I", 1);
            }

            free(buffer);
            free(lower_buffer);
            last_size = current_size;

        }

        sleep(1);
    }

    close(serial_fd);
    return 0;
}