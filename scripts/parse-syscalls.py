with open("syscalls.txt", "r") as f:
    ls = f.read().split("\n")

print("[")
for l in ls:
    hash, name = l.split()
    print("\"{}\",".format(name))
print("]")
