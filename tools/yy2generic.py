#!/usr/bin/env python3

def hex2asciiAndOct(hex_chunk) :
    generic = ""
    parts=hex_chunk.split('\\x')
    for part in parts[1:] :
        value=int(part,16)
        if value > 127 or value < 32 :
            byte ="\\"+oct(value)[2:]
        else :
            byte=chr(value)
        generic+=byte
    return generic

def convert(line) :
    print("C -> " + line)
    args = line.split(' ')
    new_line = args[0]
    if len(args) > 1 :
        new_line += " "
        for arg in args[1:] :
            chunks = arg.split('"')
            if len(chunks) > 0 :
                new_line +=c hunks[0]
                for part in chunks[1:] :
                    new_line += '"'
                    if len(part) > 2 :
                        if not (part[0]=='\\' and part[1]=='x') :
                            new_line += part 
                        else:
                            new_line +=  hex2asciiAndOct(part) 
            else :
                new_line += " " + arg
            new_line += " "
    args = new_line.split('<')
    n2_line = args[0]
    if len(args) > 1 :
        n2_line += "<"
        for arg in args[1:] :
            chunks = arg.split('>')
            if len(chunks[0])>2 and chunks[0][0]=='\\' and chunks[0][1]=='x' :
                n2_line += hex2asciiAndOct(chunks[0])
            else:
                n2_line += chunks[0]
            if len(chunks) > 0 :
                for part in chunks[1:] :
                    n2_line += '>' + part
                n2_line += '>'
            else :
                n2_line += chunks[0]
            n2_line += "<"

    return n2_line

if __name__ == '__main__':
    import sys

    for line in sys.stdin :
        print("L ->" + line)
        print(convert(line[:-1]))

