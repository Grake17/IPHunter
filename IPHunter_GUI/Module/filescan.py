"""# ======================================================================================================================
# Scan file
# ======================================================================================================================


from tkinter import *  # Import GUI


def filescan(page,style_page):
    scan = Toplevel(page)
    scan.geometry("300x150")
    scan.resizable(False, False)
    scan.title("IpHunter.exe")
    scan.iconbitmap("img\g.ico")
    scan.config(bg=style_page[0])

    scnatop = Frame(scan, bg=style_page[0])
    scantitle = Label(scnatop, text="Insert ip file path for scan", font=("Arial", 15), relief=SUNKEN, bg=style_page[1])
    scantitle.grid(row=0, column=0, sticky="nswe", padx=10, pady=10)
    scan_entry = Entry(scnatop)
    scan_entry.grid(row=1,column=0, sticky="nswe", padx=20, pady=10)
    scan_button = Button(scnatop,text="Start the super scan!")
    scan_button.grid(row=2, column=0, sticky="nswe", padx=20, pady=10)
    scan_exit = Button(scnatop, text="Exit",command = scan.destroy)
    scan_exit.grid(row=2, column=0, sticky="nswe", padx=20, pady=10)
    scnatop.columnconfigure(0, weight=1)
    scnatop.pack(fill="x")

    scan.grab_set()

def scan_this():
    f = open("C:\\Users\giuli\PycharmProjects\IP\Cybeze\Module\ip_pietro.txt", "r")

    list = f.read().replace('\n', ',')
    list2 = list.split(",")

    for x in list2:
        print(x)
        y = x.split()
        result = controlip(x)
        if result != "The input IP is invalid":
            ip = input.get()
            result = controlip(ip)
            note = result
            # The input IP is invalid
            if note == "The input IP is invalid":
                stamp = "C:\IpHunter>Insert Ip: " + ip + "\nThe input IP is invalid.\n\nInsert a new Ip for serch again."
                response.delete(1.0, END)
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
                response.delete(1.0, END)
                response.insert(END, data)

            # Ip is in your netowork
            elif note[0] == "The ip is in your network":
                if login_color[3] == True:
                    stamp = "C:\IpHunter>Insert IP: " + note[0] + "\n" + note[1] + "\n\nClose the other window to continue....."
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
                    test_if_log(IPv4)"""
