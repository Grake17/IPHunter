#=======================================================================================================================
# SSL Functions
#=======================================================================================================================
import socket
import ssl
from tkinter import *

def findssl(ssl_input,ssl_response):
    hostname = ssl_input.get()
    ssl_input.delete(0,END)
    context = ssl.create_default_context()
    try:

        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_response.delete(1.0,END)
                ssl_response.insert(END,"C:\IpHunter>Insert Site: " + hostname + "\nThis host use " + str(ssock.version()) + " certificate.\n\nInsert a new SITE for serch again.")

    except:
        ssl_response.delete(1.0, END)
        ssl_response.insert(END, "C:\IpHunter>Insert Site: " + hostname + "\nCan't find a ssl certificate.\n\nCheck your network and insert a new SITE for serch again.")


