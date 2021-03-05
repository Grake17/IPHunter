# ======================================================================================================================
# Start program
# ======================================================================================================================

from IPHunter_GUI.Module.Module1 import controlip   # Import Module1
from IPHunter_GUI.Module.Module2 import whoistest  # Import Module2
from IPHunter_GUI.Module.Module3 import *  # Import Module3
from IPHunter_GUI.Module.DomainScan import dscan  # Import DomainScan
from IPHunter_GUI.Module.loginoperation import *  # Import login function
from IPHunter_GUI.Module.nmacpscan import *   # Import namp function
from IPHunter_GUI.Module.sslscan import * # Import ssl scan
from IPHunter_GUI.page.recover_password.credential_recover import *
from PIL import ImageTk
from PIL import Image as gg

from tkinter import *  # Import GUI
from tkinter import ttk

import os
from datetime import datetime
import socket
import random

# ======================================================================================================================
# GUI
# ======================================================================================================================
root = Tk()
root.geometry("700x700")
root.resizable(False, False)
root.title("IpHunter.exe")
root.iconbitmap("img\g.ico")

global login_color
login_color = ["#cb3234","white","Login",False]


style_page = ["gainsboro","#A9A9A9"]
background_image = ImageTk.PhotoImage(gg.open("img\sfondo.png"))

running = True

# Drop Info
option = [
    "-Scan IPv4----",
    "-Scan DNS----",
    "-Scan Domain",
    "-Scan SSL-----",
    "-Scan Email---",
    "-Scan Network",
    "-Access LanDB"
]
clicked = StringVar()
clicked.set(option[0])

def startprocess():
    global running
    running = True

def stopprocess():
    global running
    running = False

def IPv4Page():

# ======================================================================================================================
# IPv4 Function
# ======================================================================================================================

# SerchIPv4
    def searchIPv4(input):
        ip = input.get()
        result = controlip(ip)
        note = result
        # The input IP is invalid
        if note == "The input IP is invalid":
            stamp = "C:\IpHunter>Insert Ip: " + ip + "\nThe input IP is invalid.\n\nInsert a new Ip for serch again."
            response.delete(1.0, END)
            response.insert(END, stamp)
            logerror(ip)

        elif note[0] == "The ip isn't in your network":
            test = whoistest(ip)
            if test == "error on connection":
                stamp = "C:\IpHunter>Insert Ip: " + ip \
                        + "\n" + note[0] \
                        + "\n" + note[1] \
                        + "\nError on connection.\n\nCheck your netowrk and try again."
                response.delete(1.0, END)
                response.insert(END, stamp)
                logerror(ip)
            else:
                data = "C:\IpHunter>Insert Ip: " + ip \
                        + "\n" + note[0] \
                        + "\n" + note[1] \
                        + "\nDomain: " + str(test[1]["domain"]) \
                        + "\nISP: " + str(test[0]["isp"]) \
                        + "\nTotalReports: " + str(test[1]["totalReports"]) \
                        + "\nIsWhiteListed?: " + str(test[1]["isWhitelisted"]) \
                        + "\nContinent: " + str(test[0]["continent"]) \
                        + "\nCountry: " + str(test[0]["country"]) \
                        + "\nRegion: " + str(test[0]["region"]) \
                        + "\nCity: " + str(test[0]["city"]) \
                        + "\nUsageType: " + str(test[1]["usageType"]) \
                        + "\n\nInsert a new Ip for serch again."
                response.delete(1.0, END)
                response.insert(END, data)
                buttonclear = Button(IPv4Buttom, text="Show More", command=moreIPv4)  # More
                buttonclear.grid(row=3, column=1, sticky="WE", padx=5, pady=5)
                logfile = data
                log(ip, logfile)

        # Ip is in your netowork
        elif note[0] == "The ip is in your network":
            if login_color[3] == True:
                stamp = "C:\IpHunter>Insert IP: " + note[0] + "\n" + note[1] + "\n\nClose the other window to continue....."
                response.delete(1.0, END)
                response.insert(END, stamp)
                querytest = inputtest(ip)
                if querytest == "exist":
                    stamp = "C:\IpHunter>Insert IP: " + ip + "\nAlready exist in the database.\n\nInsert a new IP for search again."
                    response.delete(1.0, END)
                    response.insert(END, stamp)
                else:
                    dbpage(note)
            else:
                stamp = "C:\IpHunter>Insert Ip: " + ip + "\nLogin and insert the IP again for Continue....."
                response.delete(1.0, END)
                response.insert(END, stamp)
                test_if_log(IPv4)



# MoreIPv4
    def moreIPv4():
        ip = input.get()
        result = controlip(ip)
        note = result

        # The input IP is invalid
        if note == "The input IP is invalid":
            stamp = "C:\IpHunter>Insert Ip: " + ip + "\nThe input IP is invalid.\n\nInsert a new Ip for search again."
            response.delete(1.0, END)
            response.insert(END, stamp)
            logerror(ip)
        elif note[0] == "The ip isn't in your network":
            test = whoistest(ip)
            if test == "error on connection":
                stamp = "C:\IpHunter>Insert Ip: " + ip \
                        + "\n" + note[0] \
                        + "\n" + note[1] \
                        + "\nError on connection.\n\nCheck your netowrk and try again."
                response.delete(1.0, END)
                response.insert(END, stamp)
                logerror(ip)
            else:
                data = "C:\IpHunter>Insert Ip: " + ip \
                        + "\n" + note[0] \
                        + "\n" + note[1] \
                        + "\nDomain: " + str(test[1]["domain"]) \
                        + "\nISP: " + str(test[0]["isp"]) \
                        + "\nTotalReports: " + str(test[1]["totalReports"]) \
                        + "\nIsWhiteListed?: " + str(test[1]["isWhitelisted"]) \
                        + "\nContinent: " + str(test[0]["continent"]) \
                        + "\nCountry: " + str(test[0]["country"]) \
                        + "\nRegion: " + str(test[0]["region"]) \
                        + "\nCity: " + str(test[0]["city"]) \
                        + "\nUsageType: " + str(test[1]["usageType"]) \
                        + "\n\nAdditional info:" \
                        + "\nLatitude: " + str(test[0]["latitude"]) \
                        + "\nLongitude: " + str(test[0]["longitude"]) \
                        + "\nTimezone: " + str(test[0]["timezone"]) \
                        + "\nCurrency: " + str(test[0]["currency"]) \
                        + "\nCurrency_symbol: " + str(test[0]["currency_symbol"]) \
                        + "\n\nLastReportedAt: " + str(test[1]["lastReportedAt"]) \
                        + "\n\nInsert a new Ip for serch again."
                response.delete(1.0, END)
                response.insert(END, data)
                buttonclear = Button(IPv4Buttom, text="Show Less", command= lambda: searchIPv4(input))  # More
                buttonclear.grid(row=3, column=1, sticky="WE", padx=5, pady=5)

        # Ip is in your netowork
        elif note[0][0] == "The ip is in your network":
            stamp = "C:\IpHunter>Insert Ip: " + note[0] + "\n" + note[1] + "\n\nClose the other window to continue....."
            response.delete(1.0, END)
            response.insert(END, stamp)
            querytest = inputtest(ip)
            if querytest == "exist":
                stamp = "C:\IpHunter>Insert Ip: " + ip + "\nAlready exist in the database.\n\nInsert a new Ip for search again."
                response.delete(1.0, END)
                response.insert(END, stamp)
            else:
                dbpage(note)


# SCan ip in file
    def scan_this(page,inputscan):
        try:
            startprocess()
            response.delete(1.0, END)
            f = open(inputscan.get(), "r")
            list = f.read().replace('\n', ',')
            list2 = list.split(",")
            page.destroy()
            for ip in list2:
                if running == True:
                    IPv4.update()
                    result = controlip(ip)
                    if result != "The input IP is invalid":
                        result = controlip(ip)
                        note = result
                        # The input IP is invalid
                        if note == "The input IP is invalid":
                            stamp = "C:\IpHunter>Insert Ip: " + ip + "\nThe input IP is invalid.\n\nInsert a new Ip for serch again.\n"
                            response.insert(END, stamp)

                        elif note[0] == "The ip isn't in your network":
                            test = whoistest(ip)
                            data = "C:\IpHunter>Insert Ip: " + ip \
                                   + "\n" + note[0] \
                                   + "\n" + note[1] \
                                   + "\nDomain: " + str(test[1]["domain"]) \
                                   + "\nISP: " + str(test[0]["isp"]) \
                                   + "\nTotalReports: " + str(test[1]["totalReports"]) \
                                   + "\nIsWhiteListed?: " + str(test[1]["isWhitelisted"]) \
                                   + "\nContinent: " + str(test[0]["continent"]) \
                                   + "\nCountry: " + str(test[0]["country"]) \
                                   + "\nRegion: " + str(test[0]["region"]) \
                                   + "\nCity: " + str(test[0]["city"]) \
                                   + "\nUsageType: " + str(test[1]["usageType"]) \
                                   + "\n\nInsert a new Ip for serch again."
                            response.insert(END, data)

                            # Ip is in your netowork
                        elif note[0] == "The ip is in your network":
                            if login_color[3] == True:
                                stamp = "C:\IpHunter>Insert IP: " + note[0] + "\n" + note[1] + "\n\nClose the other window to continue....."
                                response.insert(END, stamp)
                                querytest = inputtest(ip)
                                if querytest == "exist":
                                    stamp = "C:\IpHunter>Insert IP: " + ip + "\nAlready exist in the database.\n\nInsert a new IP for search again.\n"
                                    response.delete(1.0, END)
                                    response.insert(END, stamp)
                                else:
                                    dbpage(note)
                            else:
                                stamp = "C:\IpHunter>Insert Ip: " + ip + "\nLogin and insert the IP again for Continue.....\n"
                                response.delete(1.0, END)
                                response.insert(END, stamp)
                                test_if_log(IPv4)
                else:
                    stamp = "\n\nC:\IpHunter>Process stop\n"
                    response.insert(END, stamp)
                    return
        except:
            stamp = "C:\IpHunter>Insert a valid path for Continue.....\n"
            response.delete(1.0, END)
            response.insert(END, stamp)

# ======================================================================================================================
# Domain Function
# ======================================================================================================================

# Search Domain
    def searchDomain(Dinput,DomainResponse):
        domain = Dinput.get()
        if domain.count(".") != 3:
            dresult = dscan(str(domain))
            if dresult["domain_name"] == None or domain.count(".") == 3:
                DomainResponse.delete(1.0,END)
                DomainResponse.insert(END,"C:\IpHunter>Insert Domain: " + domain + "\nThe input domain is invalid.\n\nCheck your network and insert a new domain for search again.")
            else:
                DomainResponse.delete(1.0, END)
                DomainResponse.insert(END,dresult)
        else:
            DomainResponse.delete(1.0, END)
            DomainResponse.insert(END,"C:\IpHunter>Insert Domain: " + domain + "\nThe input domain is invalid.\n\nInsert a new domain for search again.")

# ======================================================================================================================
# DB Function
# ======================================================================================================================

# White list function
    def white_list(db):
        ip = input.get()
        report = "True"
        info = [ip,report,login_color[2]]
        queryresult = tableinsert(info)
        if queryresult == "Add success":
            stamp = "C:\IpHunter>Insert Ip: " + ip + "\nIs now in whitelist.\n\nInsert a new Ip for search again."
            response.delete(1.0, END)
            response.insert(END, stamp)
        else:
            stamp = "C:\IpHunter>Insert Ip: Error on add the data on the DB"
            response.delete(1.0, END)
            response.insert(END, stamp)

        db.destroy()

# Black list function
    def black_list(db):
        ip = input.get()
        report = "False"
        info = [ip, report, login_color[2]]
        queryresult = tableinsert(info)
        if queryresult == "Add success":
            stamp = "C:\IpHunter>Insert Ip: " + ip + "\nIs now in blacklist.\n\nInsert a new Ip for search again."
            response.delete(1.0, END)
            response.insert(END,stamp)
        else:
            stamp = "C:\IpHunter>Insert Ip: Error on add the data on the DB"
            response.delete(1.0, END)
            response.insert(END, stamp)

        db.destroy()

# Exit dbpage function
    def dbexit(note,db):
        db.destroy()
        stamp = "C:\IpHunter>Insert Ip: " + note[0] + "\n" + note[1] + "\nExit from page success.....\n\nInsert a new IP for serch again."
        response.delete(1.0, END)
        response.insert(END, stamp)

# ======================================================================================================================
# DNS Function
# ======================================================================================================================

    def searchDNS(dns_input,dns_response):
            dnsaddress = dns_input.get()
            dns_response.delete(1.0, END)
            try:
                dns_ipres = controlip(dnsaddress)
                if dns_ipres != "The input IP is invalid":
                    name = socket.gethostbyaddr(dnsaddress)
                    stamp = "C:\IpHunter>Insert Ip: " + dnsaddress + "\nThis dns ip is of: " + name[0] + "\n\nInsert a new DNS or IP for search again."
                    dns_response.insert(END, stamp)
                else:
                    try:
                        addr1 = socket.gethostbyname(dnsaddress)
                        stamp = "C:\IpHunter>Insert DNS: " + dnsaddress + "\nThis dns's ip is: " + addr1 + "\n\nInsert a new DNS or IP for search again."
                        dns_response.insert(END, stamp)
                    except:
                        stamp = "C:\IpHunter>Insert DNS: " + dnsaddress + "\nThis dns's ip is invalid \n\nInsert a new DNS or IP for search again."
                        dns_response.insert(END, stamp)
            except:
                stamp = "C:\IpHunter>Insert DNS: " + dnsaddress + "\nConnection error \n\nCheck your network again."
                dns_response.insert(END, stamp)
# ======================================================================================================================
# Other Function
# ======================================================================================================================

# Get Mode
    def show(page):
        mode = clicked.get()
        if mode == "-Scan IPv4----":
            page.destroy()
            IPv4Page()
        elif mode == "-Scan DNS----":
            page.destroy()
            dns_page()
        elif mode == "-Scan Domain":
            page.destroy()
            DomainPage()
        elif mode == "-Scan SSL-----":
            page.destroy()
            ssl_page()
        elif mode == "-Scan Network":
            page.destroy()
            nmap_page()
        elif mode == "-Access LanDB":
            if login_color[3] == True:
                page.destroy()
                db_main_page()
            else:
                test_if_log(page)
        elif mode == "-Scan Email---":
            page.destroy()
            mail_page()


#Clear
    def clear(text):
        text.delete(1.0,END)

#Invalid InputLog
    def logerror(ip):
        if os.path.isdir("LogError") == False:
            os.system("cmd /c mkdir LogError")

        time = datetime.now()
        time = time.strftime("%d-%b-%Y_%H-%M-%S")
        f=open("LogError/"+str(time)+".txt","w")
        f.write("Insert Ip: " + ip + "\nResponse: The input IP is invalid.")
        f.close()

#Valid Input Log
    def log(ip, logfile):
        if os.path.isdir("Log") == False:
            os.system("cmd /c mkdir Log")

        time = datetime.now()
        time = time.strftime("%d-%b-%Y_%H-%M-%S")
        f = open("Log/" + str(time) + ".txt", "w")
        f.write("Insert Ip: " + ip + "\n\nResponse: \n" + logfile)
        f.close()

# ======================================================================================================================
# Login & Register Page
# ======================================================================================================================

    def log_reg_page(page):
        login = Toplevel(root)
        login.geometry("300x300")
        login.resizable(False, False)
        login.title("IpHunter.exe")
        login.iconbitmap("img\g.ico")
        login.config(bg=style_page[0])

        def login_page():

            log_top = Frame(login,bg=style_page[0])

            login_title_frame = Frame(log_top,bg=style_page[0])
            login_title = Label(login_title_frame, text="Login Page", font=("Arial", 17), relief=SUNKEN, bg=style_page[1])
            login_title.grid(row=0,column=0,sticky="nswe", padx=5, pady=5)
            login_title_frame.grid_columnconfigure(0,weight=1)
            login_title_frame.pack(fill="x")

            login_entry_frame = Frame(log_top,bg=style_page[0])
            login_name = Label(login_entry_frame, text="Insert Username: ",bg=style_page[0])
            login_name.grid(row=1, column=0, sticky="nswe", padx=5, pady=5)
            log_input1 = Entry(login_entry_frame)
            log_input1.grid(row=1, column=1, sticky="nswe", padx=5, pady=5)
            login_password = Label(login_entry_frame, text="Insert Password: ",bg=style_page[0])
            login_password.grid(row=2, column=0, sticky="nswe", padx=5, pady=5)
            log_input2 = Entry(login_entry_frame,show="*")
            log_input2.grid(row=2, column=1, sticky="nswe", padx=5, pady=5)
            login_entry_frame.columnconfigure(0,weight=1)
            login_entry_frame.columnconfigure(1, weight=2)
            login_entry_frame.pack(fill="x",padx=20,pady=10)

            login_buttom_frame = Frame(log_top,bg=style_page[0])
            log_text_box = Label(login_buttom_frame,bg=style_page[0])
            log_text_box.grid(row=2, columnspan=2)
            login_submit = Button(login_buttom_frame, text="Submit",command = lambda : submit(log_input1,log_input2,log_text_box))
            login_submit.grid(row=3, columnspan=2, sticky="nswe", padx=20, pady=10)
            login_register = Button(login_buttom_frame, text="Register", bg="#cb3234", fg="white",command= lambda: changeregister(log_top))
            login_register.grid(row=4, columnspan=2, sticky="nswe", padx=20, pady=5)
            login_recover = Button(login_buttom_frame, text="Forgot Password?",command=lambda: credential_recover(login, style_page))
            login_recover.grid(row=5, column=0, sticky="nswe", padx=10, pady=5)
            login_exit = Button(login_buttom_frame, text="Exit",command=login.destroy)
            login_exit.grid(row=5, column=1, sticky="nswe", padx=10, pady=5)
            login_buttom_frame.grid_columnconfigure(0,weight=1)
            login_buttom_frame.grid_columnconfigure(1, weight=1)

            login_buttom_frame.pack(fill="x",padx=20)

            log_top.pack(fill="x")

            log_top.grab_set()

        def register_page():

            reg_top = Frame(login)

            reg_title_frame = Frame(reg_top,bg=style_page[0])
            reg_title = Label(reg_title_frame, text="Register Page", font=("Arial", 17), relief=SUNKEN, bg=style_page[1])
            reg_title.grid(row=0, column=0, sticky="nswe", padx=5, pady=5)
            reg_title_frame.grid_columnconfigure(0, weight=1)
            reg_title_frame.pack(fill="x")

            reg_entry_frame = Frame(reg_top,bg=style_page[0])
            reg_name = Label(reg_entry_frame, text="Insert Username: ",bg=style_page[0])
            reg_name.grid(row=1, column=0, sticky="nswe", padx=5, pady=5)
            reg_input1 = Entry(reg_entry_frame)
            reg_input1.grid(row=1, column=1, sticky="nswe", padx=20, pady=10)
            reg_password = Label(reg_entry_frame, text="Insert Password: ",bg=style_page[0])
            reg_password.grid(row=2, column=0, sticky="nswe", padx=5, pady=5)
            reg_input2 = Entry(reg_entry_frame,show="*")
            reg_input2.grid(row=2, column=1, sticky="nswe", padx=20, pady=10)
            reg_email = Label(reg_entry_frame, text="Insert Email: ", bg=style_page[0])
            reg_email.grid(row=3, column=0, sticky="nswe", padx=5, pady=5)
            reg_input3 = Entry(reg_entry_frame)
            reg_input3.grid(row=3, column=1, sticky="nswe", padx=20, pady=10)
            reg_entry_frame.columnconfigure(0, weight=1)
            reg_entry_frame.columnconfigure(1, weight=2)
            reg_entry_frame.pack(fill="x")

            reg_buttom_frame = Frame(reg_top,bg=style_page[0])
            reg_text_box = Label(reg_buttom_frame,bg=style_page[0])
            reg_text_box.grid(row=3, column=0)
            reg_submit = Button(reg_buttom_frame, text="Register", bg="#cb3234", fg="white",command=lambda: registeruser(reg_input1,reg_input2,reg_input3,reg_text_box))
            reg_submit.grid(row=4, column=0, sticky="nswe", padx=20, pady=5)
            reg_register = Button(reg_buttom_frame, text="Back to Login",command=lambda: changelogin(reg_top))
            reg_register.grid(row=5, column=0, sticky="nswe", padx=20, pady=5)
            reg_exit = Button(reg_buttom_frame, text="Exit", command=login.destroy)
            reg_exit.grid(row=6, column=0, sticky="nswe", padx=20, pady=5)
            reg_buttom_frame.grid_columnconfigure(0, weight=1)
            reg_buttom_frame.pack(fill="x")

            reg_top.pack(fill="x")

            reg_top.grab_set()

        def changelogin(pagelog):
            pagelog.destroy()
            login_page()

        def changeregister(pagelog):
            pagelog.destroy()
            register_page()

        def submit(log_input1,log_input2,log_text_box):
            name = log_input1.get()
            password = log_input2.get()
            if log_input1.get():
                if log_input2.get():
                    query_login = test_login(name,password)
                    if query_login == "The password is invalid":
                        log_text_box.configure(text=query_login, fg="#cb3234")
                    else:
                        login_color[0] = "#191970"
                        login_color[2] = "Login as: " + name
                        login_color[3] = True
                        show(page)
                        login.destroy()
                else:
                    log_text_box.configure(text="Password incorrect.",fg="#cb3234")
            else:
                log_text_box.configure(text="Input File empty.",fg="#cb3234")

        def registeruser(reg_input1,reg_input2,reg_input3,reg_text_box):
            name = reg_input1.get()
            password = reg_input2.get()
            email = reg_input3.get()
            if reg_input1.get():
                if reg_input2.get():
                    if reg_input3.get():
                        query_login = do_reg(name, password,email)
                        if query_login != "User already register":
                            reg_text_box.configure(text=query_login, fg="green")
                            reg_input1.delete(0, END)
                            reg_input2.delete(0, END)
                            reg_input3.delete(0, END)
                        else:
                            reg_text_box.configure(text=query_login, fg="#cb3234")
                            reg_input1.delete(0, END)
                            reg_input2.delete(0, END)
                            reg_input3.delete(0, END)
                    else:
                        reg_input1.delete(0, END)
                        reg_input2.delete(0, END)
                        reg_input3.delete(0, END)
                        reg_text_box.configure(text="Input File empty.", fg="#cb3234")
                else:
                    reg_input1.delete(0, END)
                    reg_input2.delete(0, END)
                    reg_input3.delete(0, END)
                    reg_text_box.configure(text="Password incorrect.",fg="#cb3234")
            else:
                reg_input1.delete(0, END)
                reg_input2.delete(0, END)
                reg_input3.delete(0, END)
                reg_text_box.configure(text="Input File empty.",fg="#cb3234")

        login_page()

    def current_user_page(page):

        current = Toplevel(root)
        current.geometry("300x200")
        current.resizable(False, False)
        current.title("IpHunter.exe")
        current.iconbitmap("img\g.ico")
        current.config(bg=style_page[0])

        current_title_frame = Frame(current,bg=style_page[0])
        current_title = Label(current_title_frame, text="Current User Page", font=("Arial", 17), relief=SUNKEN, bg=style_page[1])
        current_title.grid(row=0, column=0, sticky="nswe", padx=5, pady=5)
        current_title_frame.grid_columnconfigure(0, weight=1)
        current_title_frame.pack(fill="x")

        current_user_info = Frame(current,bg=style_page[0])
        current_user_name = Label(current_user_info,text=login_color[2],bg="#191970",fg="white")
        current_user_name.grid(row=1, column=0, sticky="nswe", padx=5, pady=10)
        current_user_logout = Button(current_user_info,text="Logout",command= lambda : logout(current,page))
        current_user_logout.grid(row=2, column=0, sticky="nswe", padx=5, pady=10)
        current_user_exit = Button(current_user_info, text="Exit",command = current.destroy)
        current_user_exit.grid(row=3, column=0, sticky="nswe", padx=5, pady=10)
        current_user_info.grid_columnconfigure(0,weight=1)
        current_user_info.pack(fill="x",padx="10",pady="10")

        current.grab_set()

    def test_if_log(page):
        if login_color[3] == True:
            current_user_page(page)
        else:
            log_reg_page(page)

    def logout(current,page):
        current.destroy()
        login_color[0] = "#cb3234"
        login_color[2] = "Login"
        login_color[3] = False
        page.destroy()
        IPv4Page()

# ======================================================================================================================
# Options and Credit Page/Function
# ======================================================================================================================

    def credits_page():

        credit = Toplevel(root)
        credit.geometry("300x290")
        credit.resizable(False, False)
        credit.title("IpHunter.exe")
        credit.iconbitmap("img\g.ico")

        credit_top = Frame(credit,bg=style_page[0])
        credit_title = Label(credit_top, text="Credits", font=("Arial", 17), relief=SUNKEN,bg=style_page[1])
        credit_title.grid(row=0, column=0, sticky="nswe", padx=5, pady=10)
        text = Label(credit_top, text="AppName: IPHunter", relief=SUNKEN, font=("Arial", 10),bg=style_page[1])
        text.grid(row=1, column=0, sticky="nswe", padx=5, pady=5)
        text1 = Label(credit_top,text="App version: 0.9.21", relief=SUNKEN,font=("Arial", 10),bg=style_page[1])
        text1.grid(row=2, column=0, sticky="nswe", padx=5, pady=5)
        text2 = Label(credit_top, text="Design by Team E", relief=SUNKEN,font=("Arial", 10),bg=style_page[1])
        text2.grid(row=3, column=0, sticky="nswe", padx=5, pady=5)
        text3 = Label(credit_top, text="Ashan Perera, Davide Marino, Giulio Monaco", relief=SUNKEN,font=("Arial", 10),bg=style_page[1])
        text3.grid(row=4, column=0, sticky="nswe", padx=5, pady=5)
        text4 = Label(credit_top, text="Other collaborator: \nLuca Longhi, Irene Marzatico \nLorenzo Romagnoli \nPietro Melillo, Andrea Vercesi", relief=SUNKEN, font=("Arial", 10),bg=style_page[1])
        text4.grid(row=5, column=0, sticky="nswe", padx=5, pady=5)
        credit_exit = Button(credit_top, text="Exit", command= credit.destroy)
        credit_exit.grid(row=6, column=0, sticky="nswe", padx=5)
        credit_top.columnconfigure(0, weight=1)
        credit_top.pack(fill="x")

        credit.grab_set()

    def option_page(page,output):

        option = Toplevel(root)
        option.geometry("300x200")
        option.resizable(False, False)
        option.title("IpHunter.exe")
        option.iconbitmap("img\g.ico")
        option.config(bg=style_page[0])

        option_top = Frame(option,bg=style_page[0])
        option_title = Label(option_top, text="Option", font=("Arial", 17), relief=SUNKEN, bg=style_page[1])
        option_title.grid(row=0, columnspan=2, sticky="nswe", padx=5, pady=15)
        option_button = Button(option_top, text="Change Color",command= lambda : change_color(page,option))
        option_button.grid(row=2, column=0, sticky="nswe", padx=5, pady=10)
        triler_button = Button(option_top, text="Show the future!",command=lambda: trailer(output,page,option))
        triler_button.grid(row=3, column=0, sticky="nswe", padx=5, pady=10)
        option_exit = Button(option_top, text="Exit", command=option.destroy)
        option_exit.grid(row=4, columnspan=2, sticky="nswe", padx=5, pady=10)
        option_top.grid_columnconfigure(0,weight=1)
        option_top.pack(fill="x")

        option.grab_set()

    def trailer(output,page,option):
        option.destroy()
        for i in range(0, 90):
            if output != None:
                output.delete(1.0,END)
                path = "start\zero\ozero" + str(i) + ".txt"
                a = open(path, "r")
                ascii = "".join(a.readlines())
                output.insert(END,ascii)
                time.sleep(0.1)
                page.update()

    def change_color(page,option):
        global style_page
        i = random.randint(1,7)
        if i == 1:
            style_page = ["gainsboro","#A9A9A9"]  # Default
        elif i == 2:
            style_page = ["#ADD8E6","#4169E1"]  # Blue
        elif i == 3:
            style_page = ["coral", "#cb3234"]  # Red
        elif i == 4:
            style_page = ["pale green", "forest green"]  # Green
        elif i == 5:
            style_page = ["thistle","dark magenta"]  # Purple
        elif i == 6:
            style_page = ["#EEE8AA","#DAA520"]  # Yellow
        elif i == 7:
            style_page = ["#DEB887","sienna"]  # Brown

        option.destroy()
        show(page)

# ======================================================================================================================
# Mail Page/Function
# ======================================================================================================================

    def mail_page():
        mail_main_page = Frame(root)

        # Title set
        map_main_title = Frame(mail_main_page)
        map_main_title1 = Label(map_main_title, text="IPHunter", font=("Arial", 40), padx=20, pady=10, relief=SUNKEN, bd=10,bg=style_page[1])
        map_main_title1.pack(fill="x")
        map_main_title2 = Label(map_main_title, text="Inser an Email for scan :", font=("Arial", 15), padx=20, pady=10,bg=style_page[0])
        map_main_title2.pack(fill="x")
        map_main_title.pack(fill="x")

        # Search Bar
        map_main_bar = Frame(mail_main_page, bg=style_page[0])
        map_logbutton = Button(map_main_bar, text=login_color[2], bg=login_color[0], fg=login_color[1],command=lambda: test_if_log(mail_main_page))
        map_logbutton.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
        map_main_input = Entry(map_main_bar)  # Input Entry
        map_main_input.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)
        map_main_buttom = Button(map_main_bar, text="Search",command=lambda: mail_print(map_main_response,map_main_input))
        map_main_buttom.grid(row=0, column=2, sticky="nswe", padx=10, pady=10)
        map_main_dropmenu = OptionMenu(map_main_bar, clicked, *option, command=lambda x: show(mail_main_page))
        map_main_dropmenu.grid(row=0, column=3, sticky="nswe", pady=10, padx=10)
        map_main_bar.grid_columnconfigure(0, weight=1)
        map_main_bar.grid_columnconfigure(1, weight=1)
        map_main_bar.grid_columnconfigure(2, weight=1)
        map_main_bar.grid_columnconfigure(3, weight=1)
        map_main_bar.pack(fill="x")

        # Output
        map_main_OutPut = Frame(mail_main_page, bg=style_page[0])
        map_main_scrool = Scrollbar(map_main_OutPut)
        map_main_response = Text(map_main_OutPut, yscrollcommand=map_main_scrool.set)
        map_main_scrool.pack(side=RIGHT, fill=Y)
        map_main_response.pack(fill="x", padx=5, pady=5)
        map_main_scrool.config(command=map_main_response.yview)
        map_main_OutPut.pack(fill="x")

        # Buttom
        map_main_Buttom = Frame(mail_main_page, bg=style_page[0])
        map_main_buttonclear = Button(map_main_Buttom, text="Clear screen", command=lambda: clear(map_main_response))  # Clear
        map_main_buttonclear.grid(row=0, column=0, sticky="WE", padx=5, pady=5)
        map_main_buttoptions = Button(map_main_Buttom, text="Options",command=lambda: option_page(mail_main_page, map_main_response))  # Exit
        map_main_buttoptions.grid(row=0, column=1, sticky="WE", padx=5, pady=5)
        map_main_buttonexit = Button(map_main_Buttom, text="Exit", command=root.quit)  # Exit
        map_main_buttonexit.grid(row=0, column=2, sticky="WE", padx=5, pady=5)
        map_main_Buttom.grid_columnconfigure(0, weight=1)
        map_main_Buttom.grid_columnconfigure(1, weight=1)
        map_main_Buttom.grid_columnconfigure(2, weight=1)
        map_main_Buttom.pack(fill="x")

        # footer
        map_main_Footer = Frame(mail_main_page, bg=style_page[0])
        map_credit = Button(map_main_Footer, text="Credits", command=credits_page)
        map_credit.grid(row=3, column=0, sticky="SWE", pady=30)
        map_main_Footer.grid_columnconfigure(0, weight=1)
        map_main_Footer.pack(fill="x", side=BOTTOM)

        mail_main_page.pack(fill="x")


    def mail_print(map_main_response,map_main_input):
        email = map_main_input.get()
        stamp = "C:\IpHunter>Insert email: " + email + "\nHey Hey Hey.....\nThis feature coming soon.... ;)"
        map_main_response.delete(1.0, END)
        map_main_response.insert(END, stamp)



# ======================================================================================================================
# NMAP Page/Function
# ======================================================================================================================

    def nmap_page():


        map_main_frame = Frame(root)

        # Title set
        map_main_title = Frame(map_main_frame)
        map_main_title1 = Label(map_main_title, text="IPHunter", font=("Arial", 40), padx=20, pady=10, relief=SUNKEN, bd=10,bg=style_page[1])
        map_main_title1.pack(fill="x")
        map_main_title2 = Label(map_main_title, text="Inser an IPv4 for scan his ports:", font=("Arial", 15), padx=20, pady=10,bg=style_page[0])
        map_main_title2.pack(fill="x")
        map_main_title.pack(fill="x")

        # Search Bar
        map_main_bar = Frame(map_main_frame,bg=style_page[0])
        map_logbutton = Button(map_main_bar, text=login_color[2], bg=login_color[0], fg=login_color[1],command=lambda :test_if_log(map_main_frame))
        map_logbutton.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
        map_main_input = Entry(map_main_bar)  # Input Entry
        map_main_input.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)
        map_main_buttom = Button(map_main_bar, text="Search", command= lambda : check_scan_ip(map_main_input,map_main_response,map_main_frame))
        map_main_buttom.grid(row=0, column=2, sticky="nswe", padx=10, pady=10)
        map_main_dropmenu = OptionMenu(map_main_bar, clicked, *option, command=lambda x: show(map_main_frame))
        map_main_dropmenu.grid(row=0, column=3, sticky="nswe", pady=10, padx=10)
        map_main_bar.grid_columnconfigure(0, weight=1)
        map_main_bar.grid_columnconfigure(1, weight=1)
        map_main_bar.grid_columnconfigure(2, weight=1)
        map_main_bar.grid_columnconfigure(3, weight=1)
        map_main_bar.pack(fill="x")

        # Output
        map_main_OutPut = Frame(map_main_frame,bg=style_page[0])
        map_main_scrool = Scrollbar(map_main_OutPut)
        map_main_response = Text(map_main_OutPut, yscrollcommand=map_main_scrool.set)
        map_main_scrool.pack(side=RIGHT, fill=Y)
        map_main_response.pack(fill="x", padx=5, pady=5)
        map_main_scrool.config(command=map_main_response.yview)
        map_main_OutPut.pack(fill="x")

        # Buttom
        map_main_Buttom = Frame(map_main_frame,bg=style_page[0])
        map_main_buttonclear = Button(map_main_Buttom, text="Clear screen", command=lambda: clear(map_main_response))  # Clear
        map_main_buttonclear.grid(row=0, column=0, sticky="WE", padx=5, pady=5)
        map_main_buttoptions = Button(map_main_Buttom, text="Options",command = lambda : option_page(map_main_frame,map_main_response))  # Exit
        map_main_buttoptions.grid(row=0, column=1, sticky="WE", padx=5, pady=5)
        map_main_buttonexit = Button(map_main_Buttom, text="Exit", command=root.quit)  # Exit
        map_main_buttonexit.grid(row=0, column=2, sticky="WE", padx=5, pady=5)
        map_main_Buttom.grid_columnconfigure(0, weight=1)
        map_main_Buttom.grid_columnconfigure(1, weight=1)
        map_main_Buttom.grid_columnconfigure(2, weight=1)
        map_main_Buttom.pack(fill="x")

        # footer
        map_main_Footer = Frame(map_main_frame,bg=style_page[0])
        map_credit = Button(map_main_Footer,text="Credits",command= credits_page)
        map_credit.grid(row=3, column=0, sticky="SWE", pady=30)
        map_main_Footer.grid_columnconfigure(0, weight=1)
        map_main_Footer.pack(fill="x", side=BOTTOM)

        map_main_frame.pack(fill="x")


        def check_scan_ip(map_main_input,map_main_response,map_main_frame):
            ipscan = map_main_input.get()
            nmapaddress = controlip(ipscan)
            if nmapaddress == "The input IP is invalid":
                stamp = "C:\IpHunter>Insert IP: " + ipscan + "\nThe input IP is invalid.\n\nInsert a new ip for search again."
                map_main_response.delete(1.0,END)
                map_main_response.insert(END,stamp)
            else:
                stamp = "C:\IpHunter>Insert IP: " + ipscan + "\nPing start.....\n\n"
                map_main_response.delete(1.0, END)
                map_main_response.insert(END, stamp)
                map_main_frame.update()
                result = try_ping(ipscan,map_main_response,map_main_frame)
                if result == "Network error":
                    stamp = "\nThe input IP is unreachable.\n\nInsert a new ip for search again."
                    map_main_response.insert(END, stamp)
                else:
                    scan_single_multi(map_main_frame,map_main_response,map_main_input)

    def scan_single_multi(map_main_frame,map_main_response,map_main_input):

        scan_port = Toplevel(map_main_frame)
        scan_port.geometry("250x250")
        scan_port.resizable(False, False)
        scan_port.title("IpHunter.exe")
        scan_port.iconbitmap("img\g.ico")


        def scan_port_single():


            scan_port_one = Frame(scan_port,bg=style_page[0])

            scan_single_title = Frame(scan_port_one,bg=style_page[0])
            ssingle_title = Label(scan_single_title, text="Single Scan Mode", font=("Arial", 17), relief=SUNKEN, bg="#dcdcdc")
            ssingle_title.grid(row=0, column=0, sticky="nswe", padx=5, pady=5)
            scan_single_title.grid_columnconfigure(0, weight=1)
            scan_single_title.pack(fill="x")

            scan_single_entry = Frame(scan_port_one,bg=style_page[0])
            scan_single_text1 = Label(scan_single_entry,text="Insert Port: ",bg=style_page[0])
            scan_single_text1.grid(row=1, column=0, sticky="nswe", padx=5, pady=5)
            scan_single_input = Entry(scan_single_entry)
            scan_single_input.grid(row=1, column=1, sticky="nswe", padx=5, pady=5)
            scan_label = Label(scan_single_entry, text="\n",bg=style_page[0])
            scan_label.grid(row=2, column=0, padx=5, pady=5)
            scan_single_entry.columnconfigure(0,weight=1)
            scan_single_entry.columnconfigure(1, weight=1)
            scan_single_entry.pack(fill="x")


            scan_single_buttom = Frame(scan_port_one,bg=style_page[0])
            scan_single_change = Button(scan_single_buttom, text="Change Multi Mode", bg="#cb3234", fg="white",command= lambda : changemulti(scan_port_one,scan_port))
            scan_single_change.grid(row=4, column=0, sticky="nswe", padx=20, pady=5)
            scan_single_search = Button(scan_single_buttom, text="Search",command=lambda : start_single_scan(scan_single_input))
            scan_single_search.grid(row=4, column=1, sticky="nswe", padx=20, pady=5)
            scan_1_995 = Button(scan_single_buttom, text="Scan main port", command=lambda : scan_main_port(map_main_input,map_main_response,scan_port,map_main_frame))
            scan_1_995.grid(row=5, columnspan=2, sticky="nswe", padx=20, pady=5)
            one_exit = Button(scan_single_buttom, text="Exit", command=scan_port.destroy)
            one_exit.grid(row=6, columnspan=2, sticky="nswe", padx=20, pady=10)
            scan_single_buttom.grid_columnconfigure(0, weight=1)
            scan_single_buttom.grid_columnconfigure(1, weight=1)
            scan_single_buttom.pack(fill="x")


            scan_port_one.pack(fill="x")

            scan_port_one.grab_set()


        def scan_multi_port(scan_port):

                scan_port_two = Frame(scan_port,bg=style_page[0])

                scan_two_title = Frame(scan_port_two,bg=style_page[0])
                smulti_title = Label(scan_two_title, text="Multi Scan Mode", font=("Arial", 17), relief=SUNKEN, bg="#dcdcdc")
                smulti_title.grid(row=0, column=0, sticky="nswe", padx=5, pady=5)
                scan_two_title.grid_columnconfigure(0, weight=1)
                scan_two_title.pack(fill="x")

                scan_two_entry = Frame(scan_port_two,bg=style_page[0])
                scan_two_text1 = Label(scan_two_entry, text="Insert Start Port: ",bg=style_page[0])
                scan_two_text1.grid(row=1, column=0, sticky="nswe", padx=5, pady=5)
                scan_two_input1 = Entry(scan_two_entry)
                scan_two_input1.grid(row=1, column=1, sticky="nswe", padx=5, pady=5)
                scan_two_entry.columnconfigure(0, weight=1)
                scan_two_entry.columnconfigure(1, weight=1)
                scan_two_text2 = Label(scan_two_entry, text="Insert End Port: ",bg=style_page[0])
                scan_two_text2.grid(row=2, column=0, sticky="nswe", padx=5, pady=5)
                scan_two_input2 = Entry(scan_two_entry)
                scan_two_input2.grid(row=2, column=1, sticky="nswe", padx=5, pady=5)
                scan_two_text = Label(scan_two_entry,bg=style_page[0])
                scan_two_text.grid(row=3, column=0)
                scan_two_entry.columnconfigure(0, weight=1)
                scan_two_entry.columnconfigure(1, weight=1)
                scan_two_entry.pack(fill="x")

                scan_two_buttom = Frame(scan_port_two,bg=style_page[0])
                scan_two_change = Button(scan_two_buttom, text="Change Single Mode", bg="#cb3234", fg="white",command= lambda : changeresingle(scan_port_two))
                scan_two_change.grid(row=4, column=0, sticky="nswe", padx=20, pady=5)
                scan_two_search = Button(scan_two_buttom, text="Search", bg="#cb3234", fg="white",command=lambda: start_multi_scan(scan_two_input1,scan_two_input2))
                scan_two_search.grid(row=4, column=1, sticky="nswe", padx=20, pady=5)
                scan_1_995_2 = Button(scan_two_buttom, text="Scan main port",command=lambda: scan_main_port(map_main_input, map_main_response, scan_port,map_main_frame))
                scan_1_995_2.grid(row=5, columnspan=2, sticky="nswe", padx=20, pady=5)
                two_exit = Button(scan_two_buttom, text="Exit", command=scan_port.destroy)
                two_exit.grid(row=6, columnspan=2, sticky="nswe", padx=20, pady=10)
                scan_two_buttom.grid_columnconfigure(0, weight=1)
                scan_two_buttom.grid_columnconfigure(1, weight=1)
                scan_two_buttom.pack(fill="x")

                scan_port_two.pack(fill="x")

                scan_port_two.grab_set()


        def changemulti(page,scan_port):
            page.destroy()
            scan_multi_port(scan_port)


        def changeresingle(page):
            page.destroy()
            scan_port_single()


        def start_single_scan(scan_single_input):
            port = scan_single_input.get()
            target = map_main_input.get()
            if port != None:
                if port.isnumeric():

                    scan_port.destroy()
                    singlescan(target, port, map_main_response, scan_port)

                else:
                    scan_port.destroy()
                    map_main_response.delete(1.0, END)
                    map_main_response.insert(END,"C:\IpHunter>Insert Port: " + port + "\nThe input port is invalid.\n\nInsert a valid port for search again.")
            else:
                scan_port.destroy()
                map_main_response.delete(1.0,END)
                map_main_response.insert(END,"C:\IpHunter>Insert Port: " + port + "\nThe input port is invalid.\n\nInsert a valid port for search again.")


        def start_multi_scan(scan_two_input1,scan_two_input2):
            port1 = scan_two_input1.get()
            port2 = scan_two_input2.get()
            target = map_main_input.get()
            if port1 != None and port2 != None:
                if port1.isnumeric() and port2.isnumeric():
                    if port1 > port2:
                        scan_port.destroy()
                        map_main_response.delete(1.0, END)
                        map_main_response.insert(END,"C:\IpHunter>Insert Port: " + port1 + " - " + port2 + "\nThe first port is greater than the second one.\n\nInsert a valid ports for search again.")
                    else:
                        scan_port.destroy()
                        multiplescan(target, port1, port2, map_main_response, scan_port,map_main_frame)
                else:
                    scan_port.destroy()
                    map_main_response.delete(1.0, END)
                    map_main_response.insert(END,"C:\IpHunter>Insert Port: " + port1 + " - " + port2 + "\nThe input ports is invalid.\n\nInsert a valid port for search again.")
            else:
                scan_port.destroy()
                map_main_response.delete(1.0,END)
                map_main_response.insert(END,"C:\IpHunter>Insert Port: " + port1 + " - " + port2 + "\nThe input ports is invalid.\n\nInsert a valid port for search again.")


        scan_port_single()

# ======================================================================================================================
# DNS page
# ======================================================================================================================

    def dns_page():

        dns = Frame(root)

        # Title set
        dns_title = Frame(dns)
        dns_title1 = Label(dns_title, text="IPHunter", font=("Arial", 40), padx=20, pady=10, relief=SUNKEN, bd=10, bg=style_page[1])
        dns_title1.pack(fill="x")
        dns_title2 = Label(dns_title, text="Insert an DNS Address:", font=("Arial", 15), padx=20, pady=10, bg=style_page[0])
        dns_title2.pack(fill="x")
        dns_title.pack(fill="x")

        # Search Bar
        dns_bar = Frame(dns, bg=style_page[0])
        db_logbutton = Button(dns_bar, text=login_color[2],bg=login_color[0],fg=login_color[1],command= lambda :test_if_log(dns))
        db_logbutton.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
        dns_input = Entry(dns_bar)  # Input Entry
        dns_input.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)
        dns_search = Button(dns_bar, text="Search", command=lambda:searchDNS(dns_input,dns_response))
        dns_search.grid(row=0, column=2, sticky="nswe", padx=10, pady=10)
        dns_dropmenu = OptionMenu(dns_bar, clicked, *option, command=lambda x: show(dns))
        dns_dropmenu.grid(row=0, column=3, sticky="nswe", pady=10, padx=10)
        dns_bar.grid_columnconfigure(0, weight=1)
        dns_bar.grid_columnconfigure(1, weight=1)
        dns_bar.grid_columnconfigure(2, weight=1)
        dns_bar.grid_columnconfigure(3, weight=1)
        dns_bar.pack(fill="x")

        # Output
        dns_output = Frame(dns, bg=style_page[0])
        dns_response = Text(dns_output)
        dns_response.grid(row=1, column=0, sticky="snwe", padx=5, pady=5)
        dns_output.grid_columnconfigure(0, weight=1)
        dns_output.pack(fill="x")

        # Buttom
        dns_button = Frame(dns, bg=style_page[0])
        dns_clear = Button(dns_button, text="Clear screen", command=lambda: clear(dns_response))  # Clear
        dns_clear.grid(row=0, column=0, sticky="WE", padx=5, pady=5)
        dns_options = Button(dns_button, text="Options",command = lambda : option_page(dns,dns_response))
        dns_options.grid(row=0, column=1, sticky="WE", padx=5, pady=5)
        dns_exit = Button(dns_button, text="Exit", command=root.quit)  # Exit
        dns_exit.grid(row=0, column=2, sticky="WE", padx=5, pady=5)
        dns_button.grid_columnconfigure(0, weight=1)
        dns_button.grid_columnconfigure(1, weight=1)
        dns_button.grid_columnconfigure(2, weight=1)
        dns_button.pack(fill="x")

        # footer
        dns_footer = Frame(dns, bg=style_page[0])
        dns_credit = Button(dns_footer,text="Credits",command= credits_page)
        dns_credit.grid(row=0, column=0, sticky="SWE", pady=30)
        dns_footer.grid_columnconfigure(0, weight=1)
        dns_footer.pack(fill="x",side=BOTTOM)

        dns.pack(fill="x")

# ======================================================================================================================
# SSL page
# ======================================================================================================================

    def ssl_page():

        ssl = Frame(root)

        # Title set
        ssl_title = Frame(ssl,bg=style_page[0])
        ssl_title1 = Label(ssl_title, text="IPHunter", font=("Arial", 40), padx=20, pady=10, relief=SUNKEN, bd=10, bg=style_page[1])
        ssl_title1.pack(fill="x")
        ssl_title2 = Label(ssl_title, text="Insert an Site Address for scan his SSL:", font=("Arial", 15), padx=20, pady=10,bg=style_page[0])
        ssl_title2.pack(fill="x")
        ssl_title.pack(fill="x")

        # Search Bar
        ssl_bar = Frame(ssl,bg=style_page[0])
        ssl_logbutton = Button(ssl_bar, text=login_color[2], bg=login_color[0], fg=login_color[1],command=lambda: test_if_log(ssl))
        ssl_logbutton.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
        ssl_input = Entry(ssl_bar)  # Input Entry
        ssl_input.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)
        ssl_search = Button(ssl_bar, text="Search", command=lambda: findssl(ssl_input, ssl_response))
        ssl_search.grid(row=0, column=2, sticky="nswe", padx=10, pady=10)
        ssl_dropmenu = OptionMenu(ssl_bar, clicked, *option, command=lambda x: show(ssl))
        ssl_dropmenu.grid(row=0, column=3, sticky="nswe", pady=10, padx=10)
        ssl_bar.grid_columnconfigure(0, weight=1)
        ssl_bar.grid_columnconfigure(1, weight=1)
        ssl_bar.grid_columnconfigure(2, weight=1)
        ssl_bar.grid_columnconfigure(3, weight=1)
        ssl_bar.pack(fill="x")

        # Output
        ssl_output = Frame(ssl,bg=style_page[0])
        ssl_response = Text(ssl_output)
        ssl_response.grid(row=1, column=0, sticky="snwe", padx=5, pady=5)
        ssl_output.grid_columnconfigure(0, weight=1)
        ssl_output.pack(fill="x")

        # Buttom
        ssl_button = Frame(ssl,bg=style_page[0])
        ssl_clear = Button(ssl_button, text="Clear screen", command=lambda: clear(ssl_response))  # Clear
        ssl_clear.grid(row=0, column=0, sticky="WE", padx=5, pady=5)
        ssl_options = Button(ssl_button, text="Options",command = lambda : option_page(ssl,ssl_response))
        ssl_options.grid(row=0, column=1, sticky="WE", padx=5, pady=5)
        ssl_exit = Button(ssl_button, text="Exit", command=root.quit)  # Exit
        ssl_exit.grid(row=0, column=2, sticky="WE", padx=5, pady=5)
        ssl_button.grid_columnconfigure(0, weight=1)
        ssl_button.grid_columnconfigure(1, weight=1)
        ssl_button.grid_columnconfigure(2, weight=1)
        ssl_button.pack(fill="x")

        # footer
        ssl_footer = Frame(ssl,bg=style_page[0])
        ssl_credit = Button(ssl_footer, text="Credits", command=credits_page)
        ssl_credit.grid(row=0, column=0, sticky="SWE", pady=30)
        ssl_footer.grid_columnconfigure(0, weight=1)
        ssl_footer.pack(fill="x", side=BOTTOM)

        ssl.pack(fill="x")

# ======================================================================================================================
# DB main page
# ======================================================================================================================

    def db_main_page():

        db_main_frame = Frame(root,bg=style_page[0])

        # Title set
        db_main_title = Frame(db_main_frame)
        db_main_title1 = Label(db_main_title, text="IPHunter", font=("Arial", 40), padx=20, pady=10, relief=SUNKEN, bd=10, bg=style_page[1])
        db_main_title1.pack(fill="x")
        db_main_title2 = Label(db_main_title, text="Welcome to the IP LAN DB:", font=("Arial", 15), padx=20, pady=10,bg=style_page[0])
        db_main_title2.pack(fill="x")
        db_main_title.pack(fill="x")

        # Search Bar
        db_main_bar = Frame(db_main_frame,bg=style_page[0])
        db_logbutton = Button(db_main_bar, text=login_color[2],bg=login_color[0],fg=login_color[1],command= lambda :test_if_log(db_main_frame))
        db_logbutton.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
        db_label = Label(db_main_bar,text="",bg=style_page[0])
        db_label.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)
        db_main_dropmenu = OptionMenu(db_main_bar, clicked, *option, command=lambda x: show(db_main_frame))
        db_main_dropmenu.grid(row=0, column=2, sticky="nswe", pady=10, padx=10)
        db_main_bar.grid_columnconfigure(0, weight=1)
        db_main_bar.grid_columnconfigure(1, weight=2)
        db_main_bar.grid_columnconfigure(2, weight=1)
        db_main_bar.pack(fill="x")


        db_output = Frame(db_main_frame,bg=style_page[0])
        tree_scroolbar = Scrollbar(db_output)
        db_tree = ttk.Treeview(db_output,yscrollcommand=tree_scroolbar.set)
        tree_scroolbar.pack(side=RIGHT, fill=Y)
        style = ttk.Style()
        style.theme_use("clam")
        style.map("Treeview",background=[("selected","#008000")])

        #Create columns
        db_tree["columns"] = ("IP","Whitelist","Client","Domain","Device","Services","UpdateBy")
        # Define Columns
        db_tree.column("#0",width=0,stretch=NO)
        db_tree.column("IP",width=70,anchor=W)
        db_tree.column("Whitelist", width=70, anchor=W)
        db_tree.column("Client", width=70, anchor=W)
        db_tree.column("Domain", width=70, anchor=W)
        db_tree.column("Device", width=70, anchor=W)
        db_tree.column("Services", width=70, anchor=W)
        db_tree.column("UpdateBy", width=70, anchor=W)
        # Define headings
        db_tree.heading("#0",text="",anchor=W)
        db_tree.heading("IP", text="IP", anchor=W)
        db_tree.heading("Whitelist", text="Whitelist", anchor=W)
        db_tree.heading("Client", text="Client", anchor=W)
        db_tree.heading("Domain", text="Domain", anchor=W)
        db_tree.heading("Device", text="Device", anchor=W)
        db_tree.heading("Services", text="Services", anchor=W)
        db_tree.heading("UpdateBy", text="UpdateBy", anchor=W)
        # Insert Date
        showall(db_tree)
        # Pack
        db_tree.pack(fill="x")
        tree_scroolbar.config(command=db_tree.yview)
        db_output.pack(fill="x",padx=20,pady=5)

        db_response = Label(db_main_frame, text="",bg=style_page[0])
        db_response.pack(fill="x")


        # Inpunt Frame
        db_input = Frame(db_main_frame, bg=style_page[0])

        # Label text
        db_label1 = Label(db_input,text="IP",bg=style_page[0])
        db_label1.grid(row=1,column=0,sticky="wsne")
        db_label2 = Label(db_input, text="Whitelist",bg=style_page[0])
        db_label2.grid(row=1, column=1,sticky="wsne")
        db_label1 = Label(db_input, text="Client", bg=style_page[0])
        db_label1.grid(row=1, column=2,sticky="wsne")
        db_label2 = Label(db_input, text="Domain", bg=style_page[0])
        db_label2.grid(row=1, column=3,sticky="wsne")
        db_label1 = Label(db_input, text="Device", bg=style_page[0])
        db_label1.grid(row=1, column=4,sticky="wsne")
        db_label2 = Label(db_input, text="Services", bg=style_page[0])
        db_label2.grid(row=1, column=5,sticky="wsne")

        # Input Text
        db_input1 = Entry(db_input)
        db_input1.grid(row=2,column=0,sticky="wsne")
        db_input2 = Entry(db_input)
        db_input2.grid(row=2, column=1,sticky="wsne")
        db_input3 = Entry(db_input)
        db_input3.grid(row=2, column=2, sticky="wsne")
        db_input4 = Entry(db_input)
        db_input4.grid(row=2, column=3, sticky="wsne")
        db_input5 = Entry(db_input)
        db_input5.grid(row=2, column=4, sticky="wsne")
        db_input6 = Entry(db_input)
        db_input6.grid(row=2, column=5, sticky="wsne")
        db_input.grid_columnconfigure(0, weight=1)
        db_input.grid_columnconfigure(1, weight=1)
        db_input.grid_columnconfigure(2, weight=1)
        db_input.grid_columnconfigure(3, weight=1)
        db_input.grid_columnconfigure(4, weight=1)
        db_input.grid_columnconfigure(5, weight=1)
        db_input.pack(fill="x",pady=10,padx=20)

        # Button
        db_buttom = Frame(db_main_frame,bg=style_page[0])
        # Add Buttom
        db_add = Button(db_buttom,text="Add",command = lambda : insert_on_db(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response))
        db_add.grid(row=1,column=0,sticky="wesn",pady=5)
        db_rem = Button(db_buttom, text="Remove", command= lambda : remove_on_db(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response))
        db_rem.grid(row=1, column=1, sticky="wesn",padx=3,pady=5)
        db_edit = Button(db_buttom, text="Edit", command= lambda : db_selection(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response,db_update))
        db_edit.grid(row=1, column=2, sticky="wesn",padx=3,pady=5)
        db_update = Button(db_buttom, text="Update", command= lambda : db_save_edit(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response,db_update))
        db_update.grid(row=1, column=3, sticky="wesn",padx=3,pady=5)
        db_refresh = Button(db_buttom, text="Refresh",command=lambda: show(db_main_frame))
        db_refresh.grid(row=1, column=4, sticky="wesn", pady=5)
        db_buttom.grid_columnconfigure(0,weight=1)
        db_buttom.grid_columnconfigure(1,weight=1)
        db_buttom.grid_columnconfigure(2,weight=1)
        db_buttom.grid_columnconfigure(3, weight=1)
        db_buttom.grid_columnconfigure(4, weight=1)

        db_buttom.pack(padx=20,fill="x")
        db_update.config(state=DISABLED)


        db_exit_options = Frame(db_main_frame,bg=style_page[0])
        db_main_options = Button(db_exit_options, text="Options",command = lambda : option_page(db_main_frame,None))
        db_main_options.grid(row=3, column=0, sticky="WE", padx=16, pady=5)
        db_main_exit = Button(db_exit_options, text="Exit", command=root.quit)
        db_main_exit.grid(row=3, column=1, sticky="WE", padx=16, pady=5)
        db_exit_options.grid_columnconfigure(0, weight=1)
        db_exit_options.grid_columnconfigure(1, weight=1)
        db_exit_options.pack(fill="x",padx=5, pady=20)

        db_footer = Frame(db_main_frame,bg=style_page[0])
        db_credits = Button(db_footer, text="Credits",command=credits_page)
        db_credits.grid(row=1,column=0, sticky="WE", padx=5, pady=5)
        db_footer.grid_columnconfigure(0,weight=1)
        db_footer.pack(fill="x",padx=5, pady=20,side=BOTTOM)

        db_main_frame.pack(fill="x")


    def insert_on_db(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response):
        db_ip = db_input1.get()
        test_db_ip = controlip(db_ip)
        if test_db_ip[0] == "The ip is in your network":
            db_whitelist = db_input2.get()
            db_client = db_input3.get()
            db_domain = db_input4.get()
            db_device = db_input5.get()
            db_services = db_input6.get()
            info = [db_ip,db_whitelist,db_client,db_domain,db_device,db_services,login_color[2]]
            db_input1.delete(0, END)
            db_input2.delete(0, END)
            db_input3.delete(0, END)
            db_input4.delete(0, END)
            db_input5.delete(0, END)
            db_input6.delete(0, END)
            test_insert_db = dbinsert(info,db_tree)
            if test_insert_db != "Already exist":
                db_response.configure(text="Succesfully Added on the DB",fg="Green")
            else:
                db_response.configure(text="IP already exist on the DB", fg="#cb3234")
        else:
            db_response.configure(text="Something go wrong, correct your input and try again",fg="#cb3234")

    def remove_on_db(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response):

            x = db_tree.selection()[0]
            db_input1.delete(0,END)
            db_input2.delete(0,END)
            db_input3.delete(0, END)
            db_input4.delete(0, END)
            db_input5.delete(0, END)
            db_input6.delete(0, END)
            for y in x:
                remip = db_tree.item(y, "values")
                dbdelete(remip)
                db_tree.delete(y)
                db_response.configure(text="Succesfully Remove on the DB", fg="Green")

    def db_selection(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response,db_update):
        try:
            selected = db_tree.selection()
            db_input1.delete(0, END)
            db_input2.delete(0, END)
            db_input3.delete(0, END)
            db_input4.delete(0, END)
            db_input5.delete(0, END)
            db_input6.delete(0, END)
            infodb = db_tree.item(selected,"values")
            db_input1.insert(0,infodb[0])
            db_input1.config(state='readonly')
            db_update.config(state=NORMAL)
            db_input2.insert(0,infodb[1])
            db_input3.insert(0, infodb[2])
            db_input4.insert(0, infodb[3])
            db_input5.insert(0, infodb[4])
            db_input6.insert(0, infodb[5])
        except IndexError:
            db_response.configure(text="Something go wrong, select a row and try again", fg="#cb3234")

    def db_save_edit(db_input1,db_input2,db_input3,db_input4,db_input5,db_input6,db_tree,db_response,db_update):
        db_input1.config(state='normal')
        db_update.config(state=DISABLED)
        db_ip = db_input1.get()
        test_db_ip = controlip(db_ip)
        if test_db_ip != "The input IP is invalid":
            db_whitelist = db_input2.get()
            db_client = db_input3.get()
            db_domain = db_input4.get()
            db_device = db_input5.get()
            db_services = db_input6.get()
            db_input1.delete(0, END)
            db_input2.delete(0, END)
            db_input3.delete(0, END)
            db_input4.delete(0, END)
            db_input5.delete(0, END)
            db_input6.delete(0, END)
            info = [db_ip, db_whitelist, db_client, db_domain, db_device, db_services, login_color[2]]
            db_modify(info)
            selected = db_tree.selection()
            db_tree.item(selected, text="",values = info)
            db_response.configure(text="Succesfully Edit on the DB", fg="Green")
        else:
            db_response.configure(text="Something go wrong, correct your input and try again", fg="#cb3234")

#=======================================================================================================================
#Domain Page
#=======================================================================================================================

    def DomainPage():
        # Page Start
        Domain = Frame(root)

        # Domain Page Title
        DomainTitle = Frame(Domain)
        Dtitle = Label(DomainTitle, text="IPHunter", font=("Arial", 40), padx=20, pady=10, relief=SUNKEN, bd=10,bg=style_page[1])
        Dtitle.pack(fill="x")
        Dtitle2 = Label(DomainTitle, text="Insert a Domain:", font=("Arial", 15), padx=20, pady=10,bg=style_page[0])
        Dtitle2.pack(fill="x")
        DomainTitle.pack(fill="x")

        # Search Bar
        DomainBar = Frame(Domain,bg=style_page[0])
        Dlogbutton = Button(DomainBar, text=login_color[2],bg=login_color[0],fg=login_color[1],command= lambda : test_if_log(Domain))
        Dlogbutton.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
        Dinput = Entry(DomainBar)
        Dinput.grid(row=0, column=1, sticky="nswe", padx=10, pady=10)
        Dserch = Button(DomainBar, text="Search", command=lambda:searchDomain(Dinput,DomainResponse))
        Dserch.grid(row=0, column=2, sticky="nswe", padx=10, pady=10)
        Dmenu = OptionMenu(DomainBar, clicked, *option,command=lambda x:show(Domain))
        Dmenu.grid(row=0, column=3, sticky="nswe", pady=10)
        DomainBar.grid_columnconfigure(0, weight=1)
        DomainBar.grid_columnconfigure(1, weight=1)
        DomainBar.grid_columnconfigure(2, weight=1)
        DomainBar.grid_columnconfigure(3, weight=1)
        DomainBar.pack(fill="x")

        # Output
        DomainOutPut = Frame(Domain,bg=style_page[0])
        domain_scroll = Scrollbar(DomainOutPut)
        DomainResponse = Text(DomainOutPut,yscrollcommand=domain_scroll.set)
        domain_scroll.pack(side=RIGHT, fill=Y)
        DomainResponse.pack(fill="x", padx=5, pady=5)
        domain_scroll.config(command=DomainResponse.yview)
        DomainOutPut.pack(fill="x")

        # Buttom
        DomainButton = Frame(Domain,bg=style_page[0])
        Dbuttonclear = Button(DomainButton, text="Clear screen", command=lambda: clear(DomainResponse))  # Clear
        Dbuttonclear.grid(row=0, column=0, sticky="WE", padx=5, pady=5)
        domain_options = Button(DomainButton, text="Options",command = lambda : option_page(Domain))
        domain_options.grid(row=0, column=1, sticky="WE", padx=5, pady=5)
        Dbuttonexit = Button(DomainButton, text="Exit", command=root.quit)  # Exit
        Dbuttonexit.grid(row=0, column=2, sticky="WE", padx=5, pady=5)
        DomainButton.grid_columnconfigure(0, weight=1)
        DomainButton.grid_columnconfigure(1, weight=1)
        DomainButton.grid_columnconfigure(2, weight=1)
        DomainButton.pack(fill="x")

        # footer
        Domainfooter = Frame(Domain,bg=style_page[0])
        domain_credit = Button(Domainfooter, text="Credits", command=credits_page)
        domain_credit.grid(row=3, column=0, sticky="WE", padx=5, pady=30)
        Domainfooter.grid_columnconfigure(0, weight=1)
        Domainfooter.pack(fill="x", side=BOTTOM)
        Domain.pack(fill="x")

# ======================================================================================================================
# IPv4 function
# ======================================================================================================================

    def dbpage(note):

        db = Toplevel(root)
        db.geometry("200x190")
        db.resizable(False, False)
        db.title("IpHunter.exe")
        db.iconbitmap("img\g.ico")

        dbtop = Frame(db,bg=style_page[0])
        dbtitle = Label(dbtop,text="Choose an option",font=("Arial", 15),relief=SUNKEN,bg=style_page[1])
        dbtitle.grid(row=0,column=0,sticky="nswe",padx=10, pady=10)
        dbwhite = Button(dbtop,text="White List",bg="white",fg="black",command= lambda :white_list(db))
        dbwhite.grid(row=1,column=0,sticky="nswe",padx=10, pady=10)
        dbblack = Button(dbtop, text="Black List", bg="black", fg="white",command= lambda :black_list(db))
        dbblack.grid(row=2, column=0, sticky="nswe", padx=10, pady=10)
        dbblack = Button(dbtop, text="Exit",command= lambda: dbexit(note,db))
        dbblack.grid(row=3, column=0, sticky="nswe", padx=10, pady=10)
        dbtop.columnconfigure(0,weight=1)
        dbtop.pack(fill="x")

        db.grab_set()

    def filescan(page):
        scan = Toplevel(page)
        scan.geometry("300x200")
        scan.resizable(False, False)
        scan.title("IpHunter.exe")
        scan.iconbitmap("img\g.ico")
        scan.config(bg=style_page[0])

        scnatop = Frame(scan, bg=style_page[0])
        scantitle = Label(scnatop, text="Insert ip file path for scan", font=("Arial", 15), relief=SUNKEN, bg=style_page[1])
        scantitle.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
        scan_entry = Entry(scnatop)
        scan_entry.grid(row=1, column=0, sticky="nswe", padx=20, pady=10)
        scan_button = Button(scnatop, text="Start the super scan!",command= lambda : scan_this(scan,scan_entry))
        scan_button.grid(row=2, column=0, sticky="nswe", padx=20, pady=10)
        scan_exit = Button(scnatop, text="Exit", command=scan.destroy)
        scan_exit.grid(row=3, column=0, sticky="nswe", padx=20, pady=10)
        scnatop.columnconfigure(0, weight=1)
        scnatop.pack(fill="x")

        scan.grab_set()

# ======================================================================================================================
# IPv4 OUT
# ======================================================================================================================


    IPv4 = Frame(root)

    # Titles
    IPv4Title = Frame(IPv4)
    title = Label(IPv4Title, text="IPHunter", font=("Arial", 40), padx=20, pady=10, relief=SUNKEN, bd=10,bg=style_page[1])
    title.pack(fill="x")
    title2 = Label(IPv4Title, text="Insert an IPv4:", font=("Arial", 15), padx=20, pady=10,bg=style_page[0])
    title2.pack(fill="x")
    IPv4Title.pack(fill="x")

    # Search Bar
    IPv4bar = Frame(IPv4,bg=style_page[0])
    logbutton = Button(IPv4bar,text=login_color[2],bg=login_color[0],fg="white",command= lambda :test_if_log(IPv4))
    logbutton.grid(row=1, column=0, sticky="nswe", padx=10, pady=10)
    input = Entry(IPv4bar)  # Input Entry
    input.grid(row=1, column=1, sticky="nswe", padx=10, pady=10)
    buttom = Button(IPv4bar, text="Search", command=lambda : searchIPv4(input))
    buttom.grid(row=1, column=2, sticky="nswe", padx=10, pady=10)
    dropmenu = OptionMenu(IPv4bar, clicked, *option,command=lambda x:show(IPv4))
    dropmenu.grid(row=1, column=3,sticky="nswe", padx=10, pady=10)
    IPv4bar.grid_columnconfigure(0, weight=1)
    IPv4bar.grid_columnconfigure(1, weight=1)
    IPv4bar.grid_columnconfigure(2, weight=1)
    IPv4bar.grid_columnconfigure(3, weight=1)
    IPv4bar.pack(fill="x")

    # Output
    IPv4OutPut = Frame(IPv4,bg=style_page[0])
    ipv4_scrollbar = Scrollbar(IPv4OutPut)
    response = Text(IPv4OutPut,yscrollcommand=ipv4_scrollbar.set)
    ipv4_scrollbar.pack(side=RIGHT, fill=Y, padx=5, pady=5)
    ipv4_scrollbar.config(command=response.yview)
    response.pack(fill="x", padx=5, pady=5)
    IPv4OutPut.pack(fill="x")

    # Buttom
    IPv4Buttom = Frame(IPv4,bg=style_page[0])
    buttonscan_file = Button(IPv4Buttom, text="Scan file",command = lambda : filescan(IPv4))  #More
    buttonscan_file.grid(row=3, column=0, sticky="WE", padx=5, pady=5)
    buttonmore = Button(IPv4Buttom, text="Show More",command = moreIPv4)  #More
    buttonmore.grid(row=3, column=1, sticky="WE", padx=5, pady=5)
    buttonclear = Button(IPv4Buttom, text="Clear screen", command= lambda:clear(response))  # Clear
    buttonclear.grid(row=3, column=2, sticky="WE", padx=5, pady=5)
    button_options = Button(IPv4Buttom, text="Options", command = lambda : option_page(IPv4,response))
    button_options.grid(row=3, column=3, sticky="WE", padx=5, pady=5)
    button_stop = Button(IPv4Buttom, text="Stop process",command = stopprocess)
    button_stop.grid(row=3, column=4, sticky="WE", padx=5, pady=5)
    button_exit = Button(IPv4Buttom, text="Exit",command = root.quit)
    button_exit.grid(row=3, column=5, sticky="WE", padx=5, pady=5)
    IPv4Buttom.grid_columnconfigure(0, weight=1)
    IPv4Buttom.grid_columnconfigure(1, weight=1)
    IPv4Buttom.grid_columnconfigure(2, weight=1)
    IPv4Buttom.grid_columnconfigure(3, weight=1)
    IPv4Buttom.grid_columnconfigure(4, weight=1)
    IPv4Buttom.grid_columnconfigure(5, weight=1)
    IPv4Buttom.pack(fill="x")

    # footer
    IPv4Footer = Frame(IPv4,bg=style_page[0])
    ipv4_credit = Button(IPv4Footer,text="Credits",command= credits_page)
    ipv4_credit.grid(row=3, column=0, sticky="WE", padx=5, pady=30)
    IPv4Footer.grid_columnconfigure(0, weight=1)
    IPv4Footer.pack(fill="x",side=BOTTOM)
    IPv4.pack(fill="x")

IPv4Page()

root.mainloop()