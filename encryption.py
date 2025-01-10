from cryptography.fernet import Fernet
import pandas as pd

def generate_key():
    return Fernet.generate_key()

def encrypt_data(file_path, key):
    fernet = Fernet(key)
    df = pd.read_csv(file_path)
    for column in df.columns:
        if df[column].dtype == object:
            df[column] = df[column].apply(lambda x: fernet.encrypt(x.encode()).decode())
    return df 