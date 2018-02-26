with open("diy_coverage.txt",'r') as fil:
    lines = fil.readlines()
    unuiqe_lines = list(set(lines))
    unuiqe_lines.sort()
    out=""
    for i in unuiqe_lines:
        out += i
with open("diy_coverage.txt", 'w+') as fil:
    fil.write(out)
