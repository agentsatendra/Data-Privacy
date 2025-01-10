import pandas as pd

def mask_data(file_path, mask_char='*'):
    df = pd.read_csv(file_path)
    for column in df.columns:
        if df[column].dtype == object:
            df[column] = df[column].apply(lambda x: mask_char * len(x))
    return df 