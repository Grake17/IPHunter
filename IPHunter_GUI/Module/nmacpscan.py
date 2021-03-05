#=======================================================================================================================
# Namp Scan
#=======================================================================================================================
from tkinter import *
from socket import *
import time
from pythonping import ping

def try_ping(ipscan,map_main_response,map_main_frame):
    result = ping(ipscan, verbose=True,count=1)
    result = str(result).strip().split("\n")
    map_main_response.insert(END,result[0]+"\n")
    map_main_frame.update()
    result = ping(ipscan, verbose=True, count=1)
    result = str(result).strip().split("\n")
    map_main_response.insert(END, result[0]+"\n")
    map_main_frame.update()
    result = ping(ipscan, verbose=True, count=1)
    result = str(result).strip().split("\n")
    map_main_response.insert(END, result[0]+"\n")
    map_main_frame.update()
    result = ping(ipscan, verbose=True, count=1)
    result = str(result).strip().split("\n")
    map_main_response.insert(END, result[0]+"\n")
    map_main_frame.update()
    test = str(result[0])
    if test.startswith("Request timed out"):
        return "Network error"
    else:
        return "Network active"

def multiplescan(target,port1,port2,map_main_response,scan_port,map_main_frame):
    try:
        startTime = time.time()
        map_main_response.delete(1.0,END)
        t_IP = gethostbyname(target)
        map_main_response.delete(1.0, END)
        map_main_response.insert(END,"C:\IpHunter>Starting scan host: "+  port1 + " - " + port2)
        for i in range(int(port1), int(port2)):
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(0.01)
            conn = s.connect_ex((t_IP, i))
            if (conn == 0):
                map_main_response.insert(END, '\nPort %d: OPEN' % (i,))
            s.close()
            map_main_frame.update()
        map_main_response.insert(END, "\nTime taken: " + str(time.time() - startTime))
    except:
        scan_port.destroy()
        map_main_response.delete(1.0, END)
        map_main_response.insert(END,"C:\IpHunter>Insert Port: " + port1 + " - " + port2 + "\nThe input port is invalid.\n\nInsert a valid port for search again.")




def singlescan(target,port,map_main_response,scan_port):
    try:
        startTime = time.time()
        t_IP = gethostbyname(target)
        map_main_response.delete(1.0,END)
        map_main_response.insert(END,"C:\IpHunter>Starting scan host: "+ t_IP + " on port " + port)
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(0.01)
        conn = s.connect_ex((t_IP, int(port)))
        if (conn == 0):
            map_main_response.insert(END,'\nPort %d: OPEN' % (int(port),))
        else:
            map_main_response.insert(END, '\nPort %d: CLOSE' % (int(port),))
        s.close()
        map_main_response.insert(END, "\nTime taken: " + str(time.time() - startTime))

    except:
        scan_port.destroy()
        map_main_response.delete(1.0, END)
        map_main_response.insert(END,"C:\IpHunter>Insert Port: " + port + "\nThe input port is invalid.\n\nInsert a valid port for search again.")


def scan_main_port(input,map_main_response,scan_port,map_main_frame):
    try:
        startTime = time.time()
        target = input.get()
        ip = gethostbyname(target)
        map_main_response.delete(1.0, END)
        map_main_response.insert(END, "C:\IpHunter>Start main scan....\n ")
        scan_port.destroy()
        f = open("img\mainportlist.txt", "r")
        list = f.read().replace(',', ' ')
        list2 = list.strip().split('\n')
        for x in list2:
            s = socket(AF_INET, SOCK_STREAM)
            s.settimeout(0.1)
            y = x.split("/")
            i = int(y[0])
            conn = s.connect_ex((ip, i))
            if (conn == 0):
                map_main_response.insert(END,'\nPort ' + str(y[0]) + " (" + str(y[1]) + ")  == OPEN \n" + str(y[2]) + '\n\n')
            map_main_frame.update()
            s.close()
        map_main_response.insert(END, "\nTime taken: " + str(time.time() - startTime))
    except:
        scan_port.destroy()
        map_main_response.delete(1.0, END)
        map_main_response.insert(END,"C:\IpHunter>Insert Ip: " + ip + "\nThe input ip is invalid.\n\nInsert a valid ip for search again.")

