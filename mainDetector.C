#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <ctype.h>

int main() {

    // declare each variables
    int serial_fd;
    struct termios tty;
    FILE * file;
    struct stat st;
    long last_size, current_size;
    char *buffer;
    char *lower_buffer;
    long bytes_to_read;
    int i;

    // open the serial port, these will be further upgrade after i obtained a simple Arduino board ^=^
    serial_fd = open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_SYNC);

    // read serial ports
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

    // just left it here for the board to startup properly
    sleep(2);

    // then again this is to tell the board that it should be ready
    // set to 6 because the word ready is 6 bits, including new line
    write(serial_fd, "READY\n", 6);
    printf("The detector is up and running!\n");

    // get file size
    stat("/var/log/snort/alerts", &st);
    last_size = st.st_size;
    
    // test the inital ping
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

            if (strstr(lower_buffer, "icmp")) {
                printf("ICMP Alert\n");
                write(serial_fd, "I", 1);
            }

            else if (strstr(lower_buffer, "http")) {
                printf("HTTP Alert\n");
                write(serial_fd, "H", 1);
            }

            else if (strstr(lower_buffer, "dns")) {
                printf("DNS Alert\n");
                write(serial_fd, "D", 1);
            }

            else if (strstr(lower_buffer, "ftp")) {
                printf("FTP Alert\n");
                write(serial_fd, "F1", 1);
            }

            else if (strstr(lower_buffer, "ssh")) {
                printf("SSH Alert\n");
                write(serial_fd, "S1", 1);
            }
            
            else if (strstr(lower_buffer, "telnet")) {
                printf("TELNET Alert\n");
                write(serial_fd, "T", 1);
            }

            else if (strstr(lower_buffer, "login failed") || strstr(lower_buffer, "authentication failure")) {
                printf("Login Failure Detected\n");
                write(serial_fd, "L", 1);
            }

            else if (strstr(lower_buffer, "syn")) {
                printf("SYN Flood\n");
                write(serial_fd, "S2", 1);
            }
            else if (strstr(lower_buffer, "fin")) {
                printf("FIN Flood\n");
                write(serial_fd, "F2", 1);
            }
            else if (strstr(lower_buffer, "rst")) {
                printf("RST Flood\n");
                write(serial_fd, "R", 1);
            }

            else if (strstr(lower_buffer, "select") || strstr(lower_buffer, "drop") || strstr(lower_buffer, "insert") || strstr(lower_buffer, "update")) {
                printf("Possible SQL Injection\n");
                write(serial_fd, "Q", 1);  // 'Q' for "Query"
            } 
            
            else if (strstr(lower_buffer, "<script") || strstr(lower_buffer, "alert(") || strstr(lower_buffer, "onerror=")) {
                printf("Possible XSS Attack\n");
                write(serial_fd, "X", 1); 
            } 
            
            else if (strstr(lower_buffer, "../") || strstr(lower_buffer, "/etc/passwd")) {
                printf("Possible Directory Traversal/File Inclusion\n");
                write(serial_fd, "U", 1); 
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