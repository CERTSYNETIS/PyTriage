import os
from keycloak import KeycloakOpenID
import jwt
from ..logging import get_logger

# --- Configuration Keycloak ---
KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "")
USE_KEYCLOAK = os.getenv("USE_KEYCLOAK", False)
LOGGER = get_logger(name="admin")

# Initialisation du client KeycloakOpenID
keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    realm_name=KEYCLOAK_REALM,
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret_key=KEYCLOAK_CLIENT_SECRET,
    verify=False,
)


def keycloak_check_globals() -> bool:
    try:
        if USE_KEYCLOAK and (
            KEYCLOAK_SERVER_URL == ""
            or KEYCLOAK_CLIENT_SECRET == ""
            or REDIRECT_URI == ""
        ):
            return False
        return True
    except Exception as ex:
        LOGGER.error(f"[keycloak_check_globals] {ex}")
        return False


def get_auth_url():
    """
    Génère l'URL d'autorisation Keycloak où l'utilisateur doit se connecter.
    """
    try:
        if keycloak_check_globals():
            auth_url = keycloak_openid.auth_url(
                redirect_uri=REDIRECT_URI, scope="openid profile email"
            )
            return auth_url
        else:
            raise Exception("Keyckloak invalid, check env variables")
    except Exception as ex:
        raise ex


def exchange_code_for_token(auth_code: str) -> dict:
    """
    Échange le code d'autorisation reçu de Keycloak contre des tokens (access token, refresh token, id token).
    """
    try:
        token_info = keycloak_openid.token(
            grant_type="authorization_code", code=auth_code, redirect_uri=REDIRECT_URI
        )
        return token_info
    except Exception as e:
        LOGGER.error(f"[exchange_code_for_token] {e}")
        # return dict()
        raise e


def refresh_access_token(refresh_token: str) -> dict:
    """
    Utilise le refresh token pour obtenir un nouvel access token.
    """
    try:
        new_token_info = keycloak_openid.refresh_token(refresh_token=refresh_token)
        return new_token_info
    except Exception as e:
        LOGGER.error(f"[refresh_access_token] {e}")
        # return dict()
        raise e


def validate_token(access_token: str) -> bool:
    """
    Valide un access token auprès de Keycloak.
    """
    try:
        token_validation = keycloak_openid.introspect(access_token)
        if token_validation:
            if token_validation.get("active", False):
                return True
        return False
    except Exception as e:
        LOGGER.error(f"[validate_token] {e}")
        return False


def get_user_info(access_token: str) -> dict:
    """
    Récupère les informations de l'utilisateur à partir de l'endpoint UserInfo.
    """
    try:
        user_info = keycloak_openid.userinfo(access_token)
        return user_info
    except Exception as e:
        LOGGER.error(f"[get_user_info] {e}")
        # return dict()
        raise e


def decode_id_token(id_token: str) -> dict:
    """
    Décode l'ID Token pour extraire les claims, y compris les groupes.
    """
    try:
        decoded_token = jwt.decode(id_token, options={"verify_signature": False})
        return decoded_token
    except Exception as e:
        print(f"[decode_id_token] {e}")
        # return dict()
        raise e


def keycloak_logout(refresh_token: str):
    try:
        keycloak_openid.logout(refresh_token=refresh_token)
    except Exception as ex:
        raise ex
