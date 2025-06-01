import serial
import time
import os
import sys

def main():
    log_path = '/var/log/snort/alerts'
    
    # Check if log file exists
    if not os.path.exists(log_path):
        print(f"Error: Log file {log_path} does not exist")
        sys.exit(1)
    
    try:
        # Open serial connection
        ser = serial.Serial('/dev/ttyUSB0', 9600, timeout=1)
        print("Serial connection established")
        time.sleep(2)
        
        # Get initial file size
        last_size = os.path.getsize(log_path)
        print(f"Initial log size: {last_size} bytes")
        
        # Initialize handshake
        ser.write(b'A')
        print("Handshake sent")
        
        print("Starting monitoring...")
        
        # Main monitoring loop
        while True:
            try:
                current_size = os.path.getsize(log_path)
                
                if current_size > last_size:
                    # Read new data from log file
                    with open(log_path, 'r') as f:
                        f.seek(last_size)
                        new_data = f.read()
                    
                    # Convert to lowercase once for efficiency
                    new_data_lower = new_data.lower()
                    
                    # Check for different alert types
                    alert_sent = False
                    
                    if 'icmp' in new_data_lower:
                        print("ICMP Alert detected")
                        ser.write(b'I')
                        alert_sent = True
                    
                    if 'http' in new_data_lower:
                        print("HTTP Alert detected")
                        ser.write(b'H')
                        alert_sent = True
                    
                    if 'syn' in new_data_lower:
                        print("SYN Flood detected")
                        ser.write(b'S')
                        alert_sent = True
                    
                    if 'fin' in new_data_lower:
                        print("FIN Flood detected")
                        ser.write(b'F')
                        alert_sent = True
                    
                    if 'rst' in new_data_lower:
                        print("RST Flood detected")
                        ser.write(b'R')
                        alert_sent = True
                    
                    if alert_sent:
                        print(f"New alert data: {new_data.strip()}")
                    
                    # Update last known size
                    last_size = current_size
                
                # Handle case where log file was rotated/truncated
                elif current_size < last_size:
                    print("Log file appears to have been rotated or truncated")
                    last_size = current_size
                
                time.sleep(1)
                
            except FileNotFoundError:
                print(f"Log file {log_path} not found, waiting...")
                time.sleep(5)
            except PermissionError:
                print(f"Permission denied reading {log_path}")
                time.sleep(5)
            except Exception as e:
                print(f"Error reading log file: {e}")
                time.sleep(5)
    
    except serial.SerialException as e:
        print(f"Serial connection error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        try:
            ser.close()
            print("Serial connection closed")
        except:
            pass

if __name__ == "__main__":
    main()