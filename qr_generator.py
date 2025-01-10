import qrcode
import io
from PIL import Image

def generate_qr_code(data):
    """
    Generate a QR code from the provided data and save as JPG
    
    Args:
        data (str): The text or URL to encode in the QR code
        
    Returns:
        BytesIO: A buffer containing the JPG image of the QR code
    """
    try:
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            box_size=10,
            border=5,
            error_correction=qrcode.constants.ERROR_CORRECT_L
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        # Create image with white background
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to RGB mode (required for JPEG)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Save image to bytes as JPG
        img_buffer = io.BytesIO()
        img.save(img_buffer, 'JPEG', quality=95)
        img_buffer.seek(0)
        
        return img_buffer
    except Exception as e:
        raise Exception(f"Error generating QR code: {str(e)}") 