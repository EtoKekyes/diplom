with open('pspoll.txt', 'r') as file:
    last_line = None
    for line in file:
        last_line = line
if last_line is not None:
    print("Latest attack was:", last_line)
else:
    print("The file is empty.")
file.close()