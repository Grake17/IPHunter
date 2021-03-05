# ======================================================================================================================
# Start terminal
# ======================================================================================================================



def menù():
    print("""

      ####################
      #                  #
      #  IP-HUNTER Menu  #
      #                  #
      ####################
      """)
    print("Please select options from Menu")
    choice = input("""
                         1 - IPv4 Search
                         2 - DNS Resolver
                         3 - Domain Search
                         4 - SSL Scan
                         5 - Network Scan
                         6 - Database
                         7 - Credit
                         8 - Exit

                         Please enter your choice: """)

    if choice == "1":
        from IPHunter_Terminal.page.ipv4.ipv4_page import ipv4_menu
        ipv4_menu(choice)
    elif choice == "2":
        pass
    elif choice == "3":
        pass
    elif choice == "4":
        pass
    elif choice == "5":
        pass
    elif choice == "6":
        pass
    elif choice == "7":
        pass
    elif choice == "8":
        pass
    else:
        print("You must only select from the given options")
        print("Please try again")

menù()