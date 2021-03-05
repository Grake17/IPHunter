# ======================================================================================================================
# IPv4 Page
# ======================================================================================================================

def ipv4_menu(text):

    print("""
            #######################
            # IP-HUNTER IPV4 Menu #
            #######################        
            """)
    print("What would you like to do? ")

    choice = input("""
                            1 - IP Search
                            2 - File Search
                            3 - Main Menu
                            4 - Exit

                            Please enter your choice: """)

    if choice == "1":
        pass
    elif choice == "2":
        pass
    elif choice == "3":
        from IPHunter_Terminal.index import menù
        menù()
    elif choice == "4":
        exit()
    else:
        print("You must only select from the given options")
        print("Please try again")


