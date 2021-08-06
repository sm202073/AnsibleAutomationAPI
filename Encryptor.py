import bcrypt as bc
import pandas as pd


'''
function that creates an encrypted csv file, keeping the headers the same
params
path: the string of the path to the csv
returns
N/A; just creates the new file
'''

def encryptor(path : str) -> None:
    with open("Encrypted_Credentials.csv", 'x') as cred_file:
        salt = bc.gensalt(12)
        credentials_data_frame = pd.read_csv(path)
        line = ""
        for credential in credentials_data_frame:
            line = line + credential + ","
        cred_file.write(line[0:-1] + "\n")
        for i in range(credentials_data_frame.shape[0]):
            line = ""
            for credential in credentials_data_frame:

                encrypted = bc.hashpw(list(credentials_data_frame[credential])[i].encode(), salt)
                line = line + str(encrypted) + ","
            cred_file.write(line[0:-1] + "\n")
            print(salt)
        return
