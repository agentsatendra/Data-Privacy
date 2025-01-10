import pandas as pd
import random
import string
from faker import Faker
import io

def anonymize_data(file_path):
    try:
        # Initialize faker for generating realistic fake data
        fake = Faker()
        
        # Read the CSV file
        df = pd.read_csv(file_path)
        
        for column in df.columns:
            if df[column].dtype == object:  # For string/object columns
                # Create a mapping of original values to anonymized values
                unique_values = df[column].unique()
                value_mapping = {}
                
                for value in unique_values:
                    if pd.isna(value):  # Preserve NULL/NaN values
                        continue
                        
                    # Generate appropriate fake data based on column name
                    if 'name' in column.lower():
                        value_mapping[value] = fake.name()
                    elif 'email' in column.lower():
                        value_mapping[value] = fake.email()
                    elif 'address' in column.lower():
                        value_mapping[value] = fake.address()
                    elif 'phone' in column.lower():
                        value_mapping[value] = fake.phone_number()
                    else:
                        # For other string columns, maintain consistency but randomize
                        value_mapping[value] = ''.join(random.choices(
                            string.ascii_letters + string.digits, 
                            k=len(str(value))
                        ))
                
                # Apply the mapping to the column
                df[column] = df[column].map(lambda x: value_mapping.get(x, x))
        
        # Convert the DataFrame to CSV string
        output = io.StringIO()
        df.to_csv(output, index=False)
        return output.getvalue()
        
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        return None 