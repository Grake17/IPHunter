#=======================================================================================================================
# Remove credentials
#=======================================================================================================================

from IPHunter_GUI.Module.loginoperation import *
from tkinter import *  # Import GUI



def credential_recover(login,style_page):
    recover = Toplevel(login)
    recover.geometry("300x200")
    recover.resizable(False, False)
    recover.title("IpHunter.exe")
    recover.iconbitmap("img\g.ico")
    recover.config(bg=style_page[0])

    def page1():
        recover_top = Frame(recover, bg=style_page[0])

        recover_title_frame = Frame(recover_top, bg=style_page[0])
        recover_title = Label(recover_title_frame, text="Credentials Recover Page", font=("Arial", 17), relief=SUNKEN, bg=style_page[1])
        recover_title.grid(row=0, column=0, sticky="nswe", padx=5, pady=5)
        recover_title_frame.grid_columnconfigure(0, weight=1)
        recover_title_frame.pack(fill="x")

        recover_entry_frame = Frame(recover_top, bg=style_page[0])
        recover_name = Label(recover_entry_frame, text="Insert Email: ", bg=style_page[0])
        recover_name.grid(row=1, column=0, sticky="nswe", padx=5, pady=5)
        recover_input1 = Entry(recover_entry_frame)
        recover_input1.grid(row=1, column=1, sticky="nswe", padx=20, pady=10)
        recover_result = Label(recover_entry_frame, text="", bg=style_page[0])
        recover_result.grid(row=2, columnspan=2, sticky="nswe", padx=5, pady=5)
        recover_entry_frame.columnconfigure(0, weight=1)
        recover_entry_frame.columnconfigure(1, weight=2)
        recover_entry_frame.pack(fill="x")

        recover_buttom_frame = Frame(recover_top, bg=style_page[0])
        recover_send = Button(recover_buttom_frame,text="Send",command = lambda :recover_page(recover_input1,recover_result,recover_name,recover_send) )
        recover_send.grid(row=6, column=0, sticky="nswe", padx=20, pady=5)
        recover_exit = Button(recover_buttom_frame, text="Exit", command=recover.destroy)
        recover_exit.grid(row=7, column=0, sticky="nswe", padx=20, pady=5)
        recover_buttom_frame.grid_columnconfigure(0, weight=1)
        recover_buttom_frame.pack(fill="x")

        recover_top.pack(fill="x")

        recover_top.grab_set()


        def recover_page(recover_input1,recover_result,recover_name,recover_send):
            email = recover_input1.get()
            result = test_email(email)
            if result == "Error: email not send":
                recover_result.config(text="Error: email not send")
            else:
                recover_name.config(text="Insert code:")
                recover_result.config(text="Email send!!!\n Insert the code for continue")
                recover_input3 = Entry(recover_entry_frame)
                recover_input3.grid(row=1, column=1, sticky="nswe", padx=20, pady=10)
                recover_send.config(command= lambda :code_check(recover_name,recover_input3,email))

        def code_check(recover_name,recover_input3,email):
            result = test_code(recover_input3.get())
            if result == "Code incorrect":
                recover_name.config(text="Code incorrect",fg="#cb3234")
            else:
                recover_name.config(text="Insert code:",fg="black")
                recover_result.config(text="Insert the new password",fg="black")
                recover_input4 = Entry(recover_entry_frame,show="*")
                recover_input4.grid(row=1, column=1, sticky="nswe", padx=20, pady=10)
                recover_send.config(command=lambda: new_cred(recover_input4,email,recover_name))

        def new_cred(recover_input4,email,recover_name):
            recover_name.config(text="Insert new passoword:")
            password = recover_input4.get()
            new_password(password,email)
            recover.destroy()


    page1()