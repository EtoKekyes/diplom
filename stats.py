def stats():
    with open('pspoll.txt', 'r') as file:
        last_line = None
        for line in file:
            last_line = line
    if last_line is not None:
        print("Latest attack was:", last_line)
    else:
        print("The file is empty.")
    file.close()



def stats():
 while True:
    match input(f"Select stats (pspoll, deauth, disas, wep, count): "):
        case "pspoll":
            with open('pspoll.txt', 'r') as file:
                last_line = None
            for line in file:
                last_line = line
            if last_line is not None:
                print("|-------------------------------------------------------------------------------|\n"
                "| PS-Poll attacks detected =",pspoll, "\n"
                "Latest", last_line)
            else:
                print("The file is empty.")
                 

        case "deauth":
            with open('pspoll.txt', 'r') as file:
                last_line = None
            for line in file:
                last_line = line
            if last_line is not None:
                print("|-------------------------------------------------------------------------------|\n"
                "| DoS Deauthentication attacks detected =",deauth, "\n"
                "Latest", last_line)
            else:
                print("The file is empty.")
             

        case "disas":
            with open('pspoll.txt', 'r') as file:
                last_line = None
            for line in file:
                last_line = line
            if last_line is not None:
                print("|-------------------------------------------------------------------------------|\n"
                "| DoS Disassociation attacks detected =",disas, "\n"
                "Latest", last_line)
            else:
                print("The file is empty.")
             

        case "wep":
            with open('pspoll.txt', 'r') as file:
                last_line = None
            for line in file:
                last_line = line
            if last_line is not None:
                print("|-------------------------------------------------------------------------------|\n"
                "| WEP APs detected =",wep, "\n"
                "Latest", last_line)
            else:
                print("The file is empty.")
             
        case "count":
            f = open("stats.txt", 'r')
            contents = f.read()
            wep = contents.count("WEP AP")
            pspoll = contents.count("PS-Poll")
            disas = contents.count("Disassociation")
            deauth = contents.count("Deauthentication")
            print("|-------------------------------------------------------------------------------|\n"
                "| Current stats:""\n"
                "| PS-Poll attacks detected =",pspoll, "\n"
                "| DoS Deauthentication attacks detected =",deauth, "\n"
                "| DoS Disassociation attacks detected =",disas, "\n"
                "| WEP APs detected =",wep)
            
        case _name: 
            print(f"Invalid mode: {_name}!")


    