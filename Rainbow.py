import sys
import hashlib

def main():
    password_dict = {} # dictionary for password{index : password} - example {1 : 10th}
    hashed_dic = {} # dictionary for hex{hash : reduction} - example {8d9407b7f819b7f25b9cfab0fe20d5b3  : 2325} 
    rainbow_dict = {} # dictionary for rainbow table{password : final_hash} - example {10th : 2d63209bc2da0f16d090b007a45fbff0}
    #full_table = {}
    
    password_dict, count = storePasswordtoDict() # create the index for the password
    hashed_dic = storeHashtoDict(count, password_dict) # get the hash and the reduction
    rainbow_dict = createRainbowTable(password_dict, hashed_dic)
    sorted_rainbow_dict = {k: v for k, v in sorted(rainbow_dict.items(), key=lambda item: item[1])}  # sort the rainbow table
    storeRainbowTable(sorted_rainbow_dict) # store RainbowTable in a text file

    user_input = getUserinput()
    validation(user_input,sorted_rainbow_dict, password_dict, hashed_dic, count)
    # with open('table.txt', 'w') as f:
    #     for index in full_table:
    #         f.write('%-5s %-15s %35s %7s\n' % (str(index), full_table[index][0].strip(), full_table[index][1],  str(full_table[index][2])))

def validation(userinput: str, sorted_rainbow_dict: dict, password_dict: dict, hashed_dic: dict, count):
    if userinput in sorted_rainbow_dict.values(): # check if the hash value is in the rainbow table
        # retrieve a list of all passwords with a matching hash
        matched_passwords = [k for k,v in sorted_rainbow_dict.items() if v == userinput]
        if passwordFound(userinput, password_dict, count, matched_passwords):
            sys.exit(0)
        
    else:   # if cant find hash in the rainbow table, keep hashing for 5 times until a match is found
        reduction = reducingFunction(userinput, count)
        find_hash = hashlib.md5(password_dict[reduction].encode()).hexdigest()

        for i in range(0, 5):
            if find_hash in sorted_rainbow_dict.values():
                matched_passwords = [k for k,v in sorted_rainbow_dict.items() if v == find_hash]
                if passwordFound(userinput, password_dict, count, matched_passwords):
                    sys.exit(0)

            reduction = reducingFunction(find_hash, count)
            find_hash = hashlib.md5(password_dict[reduction].encode()).hexdigest()
            
        print("Password not found")

def passwordFound(userinput: str,password_dict: dict, count, matched_passwords: list):
    for password in matched_passwords:
        try_password = password
        for i in range(0,5):
            hashvalue = hashlib.md5(try_password.encode()).hexdigest()
            if hashvalue == userinput:
                print("Password found! It is " + try_password)
                return True
            try_password = password_dict[(int(hashvalue, 16) % count) + 1] # get next password in the chain
    
    return False

        
def storePasswordtoDict():
    password_dict = {}
    count = 0
    with open(sys.argv[1]) as f:
        for line in f:
            count += 1
            password_dict[count] = line.strip()

    print("Total number of passwords: " + str(count))
    return password_dict, count


def storeRainbowTable(rainbow: dict):
    with open("Rainbow.txt", 'w') as f:
        count = 0
        for password in rainbow:
            count += 1
            f.write('%-20s %35s\n' % (password.strip(), str(rainbow[password])))

        print("Total number of passwords in Rainbow Table: " + str(count))


def storeHashtoDict(count: int, password_dict: dict):
    hashed_dict = {}
    #full_table = {}
    
    for i in range(1,count+1):
        hashed_password = hashlib.md5(password_dict[i].encode()).hexdigest()
        reduction = reducingFunction(hashed_password, count)  # reduction function is a simple mod function
        #result = [password_dict[i], hashed_password, reduction]
        #full_table[i] = result
        hashed_dict[hashed_password] = reduction

    return hashed_dict# , full_table


def reducingFunction(val: str, count: int):
    return (int(val, 16) % count) + 1   # simple mod function


def createRainbowTable(password_dict: dict, hashed_dict: dict):
    rainbow_dict = {}
    marked_list = [] # list to store marked passwords
    count = 0

    for index in password_dict:
        if password_dict[index] not in marked_list:
            reduction = index
            for i in range(5):  # loop 5 times 
                password = password_dict[reduction]   # retrieve password from the dictionary
                hashed_password = hashlib.md5(password.encode()).hexdigest()   # hash the password
                reduction = hashed_dict[hashed_password]   # retrieve the reduction value from the dictionary
                if password not in marked_list:
                    marked_list.append(password)

            rainbow_dict[password_dict[index]] = hashed_password
            count += 1

    return rainbow_dict


def getUserinput():
    flag = False

    while not flag:
        value = input("Please enter hash value: ")
        if(len(value) != 32):
            print("\n###Please enter a 32 char hash value###\n")
        else:
            flag = True

    return value

    
main()
