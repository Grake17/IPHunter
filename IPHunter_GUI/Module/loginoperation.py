#=======================================================================================================================
# Login Functions
#=======================================================================================================================
import hashlib
import sqlite3
import smtplib
import random
import string
import ssl

# Check if table exist
def table_login_check():
    # db connection
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS loginlist (
                username text,
                password text,
                email text,
                recovercode text
                )""")
    conn.commit()
    conn.close()

# Register user
def do_reg(name,password,email):
    table_login_check()
    hash = create_hash(password)
    stat = [name,hash,email,None]
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    sqlite_select_query = """SELECT * from loginlist where email = ?"""
    c.execute(sqlite_select_query, (email,))
    data = c.fetchone()
    if data is None:
        c.execute("INSERT INTO loginlist VALUES (?,?,?,?);", stat)
        conn.commit()
        conn.close()
        return "Register success"
    else:
        conn.commit()
        conn.close()
        return "User already register"

# Test if user is register
def test_reg(name):
    table_login_check()
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    sqlite_select_query = """SELECT * from loginlist where username = ?"""
    c.execute(sqlite_select_query, (name,))
    data = c.fetchone()
    if data is None:
        conn.commit()
        conn.close()
        return "user isn't Register success"
    else:
        conn.commit()
        conn.close()

        return "User already register"

# Login
def test_login(name,password):
    result = test_reg(name)
    hash = create_hash(password)
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    if result == "User already register":
        sqlite_select_query = """SELECT * from loginlist where username = ?"""
        c.execute(sqlite_select_query, (name,))
        query_result = c.fetchone()
        conn.commit()
        conn.close()
        if query_result[0] == name and query_result[1] == hash:
            return "Login Success"
        else:
            return "The password is invalid"
    else:
        return "The password is invalid"

# Create hash
def create_hash(password):
    text3 = password + "IPHunter"
    hash_object = hashlib.md5(text3.encode())
    password2 = hash_object.hexdigest()
    return password2

# Test if insert mail is in db
def test_email(email):

    table_login_check()
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    qlite_select_email = """SELECT * from loginlist where email = ?"""
    c.execute(qlite_select_email, (email,))
    query_result = c.fetchone()
    conn.commit()
    conn.close()
    if query_result != None:
        if query_result[2] == email:
            code = create_code(email)
            result = send_email(email,code)
            return result
        else:
                return "Wrong email"
    else:
        return "Wrong email"


# send email
def send_email(email,code):
    try:
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = "iphunter70@gmail.com"  # Enter your address
        receiver_email = email  # Enter receiver address
        password = "RDlttvzzcPJQEDZDiMwW"
        message = 'Subject: {}\n\n{}'.format("Restore Password", code)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
            server.close()
    except:
        result = "Error: email not send"
        return result

# Create cose for email
def create_code(email):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(6))
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    c.execute("""UPDATE loginlist SET recovercode = :recovercode  WHERE email = :email""",{
        "recovercode": result_str,
        "email": email
    })
    conn.commit()
    conn.close()
    return result_str

#Check code
def test_code(code):
    table_login_check()
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    qlite_select_email = """SELECT * from loginlist where recovercode = ?"""
    c.execute(qlite_select_email, (code,))
    query_result = c.fetchone()
    conn.commit()
    conn.close()
    if query_result == None:
        return "Code incorrect"
    else:
        return "Code correct"

# Change passoword
def new_password(text,email):
    conn = sqlite3.connect("IPHunter.db")
    c = conn.cursor()
    text2 = create_hash(text)
    c.execute("""UPDATE loginlist SET password = :password  WHERE email = :email""", {
        "password": text2,
        "email": email
    })
    conn.commit()
    conn.close()


