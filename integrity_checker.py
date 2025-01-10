import hashlib

def calculate_file_hash(file, algorithm='sha256'):
    # Convert algorithm name to lowercase
    algorithm = algorithm.lower()
    
    # Initialize hash function
    try:
        hash_func = hashlib.new(algorithm)
    except ValueError:
        # Fallback to sha256 if algorithm is not supported
        hash_func = hashlib.sha256()
    
    # Read and hash file in chunks
    chunk_size = 8192
    file.seek(0)  # Reset file pointer to beginning
    
    while True:
        chunk = file.read(chunk_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode()
        hash_func.update(chunk)
            
    file.seek(0)  # Reset file pointer after reading
    return hash_func.hexdigest() 