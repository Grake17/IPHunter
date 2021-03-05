#=======================================================================================================================
# Module 3- Ip on the same network
#=======================================================================================================================

import sqlite3
from tkinter import *

def tabletest():

    # db connection
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS iplist (
            ip text,
            whitelist text,
            client text,
            domain text,
            device text,
            services text,            
            updateby text
            )""")
    conn.commit()
    conn.close()

def inputtest(ip):
    tabletest()
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    sqlite_select_query = """SELECT * from iplist where ip = ?"""
    c.execute(sqlite_select_query, (ip,))
    data = c.fetchone()
    if data is None:
        conn.commit()
        conn.close()
        return "notexist"
    else:
        conn.commit()
        conn.close()
        return "exist"


def tableinsert(info):
    tabletest()
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    c.execute("INSERT INTO iplist (ip,whitelist,updateby) VALUES (?,?,?);", info)
    conn.commit()
    conn.close()
    return "Add success"

#=======================================================================================================================
# Module 3- DB page command
#=======================================================================================================================

# Print all db function
def showall(db_tree):
    tabletest()
    for i in db_tree.get_children():
        db_tree.delete(i)
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    sqlite_select_query = """SELECT * from iplist"""
    c.execute(sqlite_select_query)
    data = c.fetchall()
    conn.close()
    y=0
    db_tree.tag_configure("oddrow", background="white")
    db_tree.tag_configure("evenrow", background="lightgreen")
    for x in data:
        if y % 2 == 0:
            db_tree.insert(parent="", index=END, iid=y, values=(x[0],x[1],x[2],x[3],x[4],x[5],x[6]),tag="oddrow")
        else:
            db_tree.insert(parent="", index=END, iid=y, values=(x[0],x[1],x[2],x[3],x[4],x[5],x[6]),tag="evenrow")
        y= y + 1

# Insert on db
def dbinsert(info,db_tree):
    tabletest()
    result = inputtest(info[0])
    if result == "notexist":
        conn = sqlite3.connect("IPHunter.db")
        c = conn.cursor()
        c.execute("INSERT INTO iplist VALUES (?,?,?,?,?,?,?);", info)
        conn.commit()
        conn.close()
        showall(db_tree)
        return "Add success"
    else:
        return "Already exist"

# Delete on db
def dbdelete(remip):
    tabletest()
    ip = remip[0]
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    c.execute("DELETE from iplist where ip = ?", (ip,))
    conn.commit()
    conn.close()

# Edit
def db_modify(info):
    tabletest()
    result = inputtest(info[0])
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    if result == "exist":
        c.execute("""UPDATE iplist SET whitelist = :whitelist, client = :client, domain = :domain, device = :device, services = :services, updateby = :updateby WHERE ip = :ip""",{
            "whitelist": info[1],
            "client": info[2],
            "domain": info[3],
            "device": info[4],
            "services": info[5],
            "updateby": info[6],
            "ip": info[0]
        })
    else:
        print(1)
    conn.commit()
    conn.close()
    return "Add success"













