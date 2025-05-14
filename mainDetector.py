import serial
import time
import os

# this is to open the serial connection to /dev/ttyUSB0 at 9600 baud rate
# then wait for 2 seconds to initialize
ser = serial.Serial('/dev/ttyUSB0', 9600, timeout = 1)
time.sleep(2)

log_path = '/var/log/snort/alerts'
last_size = os.path.getsize(log_path)
# log all the alerts through an app called Snort

# initialize the handshake
ser.write(b'A')

# start the monitoring
while True:
    current_size = os.path.getsize(log_path)
    if current_size > last_size:
        with open(log_path, 'r') as f:
            f.seek(last_size)
            new_data = f.read()

            if 'icmp' in new_data.lower():
                print("ICMP Alert")
                ser.write(b'I')
            elif 'http' in new_data.lower():
                print("HTTP Alert")
                ser.write(b'H')
            elif 'syn' in new_data.lower():
                print("SYN Flood")
                ser.write(b'S')
            elif 'fin' in new_data.lower():
                print("FIN Flood")
                ser.write(b'F')
            elif 'rst' in new_data.lower():
                print("Rst Flood")
                ser.write(b'R')
        
        last_size = current_size
    time.sleep(1)