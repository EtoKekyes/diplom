import datetime

#f = open("stats.txt")
#contents = f.read()
# wep = contents.count("WEP AP")
# pspoll = contents.count("PS-Poll")
# disas = contents.count("Disassociation")
#deauth = contents.count("Deauthentication")
# print("|-------------------------------------------------------------------------------|\n"
#       "| Current stats:""\n"
#       "| PS-Poll attacks detected =",pspoll, "\n"
#       "| DoS Deauthentication attacks detected =",deauth, "\n"
#       "| DoS Disassociation attacks detected =",disas, "\n"
#       "| WEP APs detected =",wep, "last known attack was at")


# Read dates from the file
f = open("stats.txt", 'r')
d = f.readline()
dt = datetime.datetime.strptime(d, '%y-%m-%d %H:%M:%S.%f')
print(dt.strftime('%Y'))
# dates = [line.strip() for line in f]

# # Convert dates to datetime objects
# date_objects = [datetime.strptime(date, '%Y-%m-%d %H:%M:%S') for date in dates]

# # Find the latest date
# latest_date = max(date_objects)
# print("The latest date is:", latest_date)
