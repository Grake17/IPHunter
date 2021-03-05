from socket import *

ip = gethostbyname("192.168.1.1")
print(ip)
f = open("C:\\Users\giuli\PycharmProjects\IP\Cybeze\img\mainportlist.txt","r")
list = f.read().replace(',', ' ')
list2= list.strip().split('\n')
for x in list2:
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(0.1)
    y = x.split("/")
    i = int(y[0])
    conn = s.connect_ex((ip, i))
    if (conn == 0):
        print('\nPort ' + str(y[0]) + " (" + str(y[1]) + ") " + str(y[2]) +  'is OPEN')
    s.close()







