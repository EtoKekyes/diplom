# f = open("stats.txt")
# for line in f:
#     print(f.read())

with open("stats.txt") as f:
    contents = f.read()
    diss = contents.count("DoS Disassociation attack")
    deauth = contents.count("DoS Deauthentication attack detected")
    print(diss, deauth)