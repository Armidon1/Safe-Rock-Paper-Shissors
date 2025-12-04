import secrets

rps = {0:"Scissors", 1:"Rock", 2:"Paper"}

def rock_paper_shissors_secure():
    return rps[secrets.randbelow(3)]

if __name__ == "__main__":
    count_rps = {"Shissors":0, "Rock":0, "Paper":0}
    print(("-"*10)+"Testing"+("-"*10))
    for i in range(1000000000):
        match rock_paper_shissors_secure():
            case "Shissors":
                count_rps["Shissors"] +=1
            case "Rock":
                count_rps["Rock"] +=1
            case "Paper":
                count_rps["Paper"] +=1
    print(f"Shissors = {count_rps['Shissors']}, Rock = {count_rps['Rock']}, Paper = {count_rps['Paper']}")
    print(("-"*10)+"Finish"+("-"*10))
    