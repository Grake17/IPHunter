# ======================================================================================================================
# IPv4 Page
# ======================================================================================================================

def search_ipv4(ip):
    from IPHunter_Terminal.Module.Module1 import *
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
            buttonclear = Button(IPv4Buttom, text="Show Less", command=lambda: searchIPv4(input))  # More
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