with open("/home/juhua/experiment/MY/protocoltaint/result/BBLs.txt") as f:
    lines = f.readlines()

for i in range(len(lines)):
    for j in range(i + 1, len(lines)):
        if lines[i].split("\t")[1] == lines[j].split("\t")[1]:
            print(lines[i])
            continue

