"""Authentication classes used to create salt and generate hashed password."""
import bcrypt
import passlib.context import CryptContext

from app.models.user import UserPasswordUpdate

pwd_context = CryptContext(schemas=["bcrypt"], deprecated="auto")