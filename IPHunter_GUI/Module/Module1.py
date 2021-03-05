#=======================================================================================================================
# Module 1- Control ip
#=======================================================================================================================

def controlip(ip):

    # Check Valid Ip
    if ip == None:
        result = "The input IP is invalid"
        return result

    if ip.count(".") != 3:
        result = "The input IP is invalid"
        return result

    splitip = ip.split(".",3)


    # Check Numbers

    if not splitip[0].isnumeric():
        result = "The input IP is invalid"
        return result
    if not splitip[1].isnumeric():
        result = "The input IP is invalid"
        return result
    if not splitip[2].isnumeric():
        result = "The input IP is invalid"
        return result
    if not splitip[3].isnumeric():
        result = "The input IP is invalid"
        return result


    # Spiacial cases

    if (ip == "127.0.0.1"):
        result = "This ip is your localhost ip"
        return result


    # Check Ip Class

    if int(splitip[0]) < 1 and int(splitip[3] < 1):
        result = "The input IP is invalid"
        return result
    elif(int(splitip[0]) < 128 ):
        lettera = "A"
    elif(int(splitip[0]) < 192):
        lettera = "B"
    elif(int(splitip[0]) < 224):
        lettera = "C"
    elif(int(splitip[0]) < 240):
        lettera = "D"
    elif(int(splitip[0]) < 255):
        lettera = "E"
    else:
        result = "The input IP is invalid"
        return result

    result1 = "The input IP is Class: "+ lettera

    if int(splitip[0]) > 255 or int(splitip[1]) > 255 or int(splitip[2]) > 255 or int(splitip[3]) > 255:
        result = "The input IP is invalid"
        return result


    # Check IP on the same network

    import socket
    IPaddr = socket.gethostbyname(socket.gethostname())
    net = IPaddr.split(".", 4)
    print(net)
    test = 0

    if lettera == "A":
       if net[0] == splitip[0]:
           test = "True"
    elif lettera == "B":
        if net[0] == splitip[0] and net[1] == splitip[1]:
            test = "True"
    elif lettera == "C" or lettera == "D" or lettera == "E":
        if net[0] == splitip[0] and net[1] == splitip[1] and net[2] == splitip[2]:
            test = "True"

    if test == "True":
        result2 = "The ip is in your network"
        return result2,result1
    else:
        result2 = "The ip isn't in your network"
        return result2,result1









