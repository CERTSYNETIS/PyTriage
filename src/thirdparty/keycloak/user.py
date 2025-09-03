from flask_login import UserMixin
import os

KEYCLOAK_ADMIN_GROUP = os.getenv("KEYCLOAK_ADMIN_GROUP", "admin").lower()


class User(UserMixin):
    def __init__(
        self,
        user_id: str,
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        groups: list,
        email_verified: bool = False,
        validate_token: bool = False,
        token_expires_in: int = 0,
    ):
        self.id = user_id
        self.username = username
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.email_verified = email_verified
        self.validate_token = validate_token
        self.token_expires_in = token_expires_in
        self.groups = list(map(lambda x: x.lower(), groups))
        self.admin = KEYCLOAK_ADMIN_GROUP in self.groups

    def get_id(self):
        return str(self.id)
