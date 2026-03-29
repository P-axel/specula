import time
from typing import Any, Dict, Optional

import requests
from requests import Response
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

from config.settings import settings
from specula_logging.logger import get_logger

logger = get_logger(__name__)


class WazuhClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
        auth_type: str = "token",  # "token" pour Wazuh API, "basic" pour l'indexer
    ) -> None:
        self.base_url = (base_url or settings.wazuh_base_url).rstrip("/")
        self.username = username or settings.wazuh_username
        self.password = password or settings.wazuh_password
        self.verify_ssl = verify_ssl if verify_ssl is not None else settings.wazuh_verify_tls
        self.timeout = timeout if timeout is not None else settings.wazuh_timeout
        self.auth_type = auth_type

        self.token: Optional[str] = None
        self.token_expire_at: float = 0.0

        if not self.base_url:
            raise ValueError("WAZUH_BASE_URL manquant")
        if not self.username:
            raise ValueError("WAZUH_USERNAME manquant")
        if not self.password:
            raise ValueError("WAZUH_PASSWORD manquant")
        if self.auth_type not in {"token", "basic"}:
            raise ValueError("auth_type doit être 'token' ou 'basic'")

        logger.info(
            "WazuhClient initialisé pour %s (auth_type=%s)",
            self.base_url,
            self.auth_type,
        )

    def authenticate(self) -> str:
        """
        Authentification par token pour l'API Wazuh.
        Ne s'utilise pas pour l'indexer en basic auth.
        """
        if self.auth_type != "token":
            raise RuntimeError("authenticate() ne doit pas être utilisé en mode basic")

        url = f"{self.base_url}/security/user/authenticate"
        params = {"raw": "true"}

        logger.debug("Authentification Wazuh sur %s", url)

        try:
            response = requests.post(
                url,
                params=params,
                auth=HTTPBasicAuth(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()
        except RequestException as exc:
            logger.error("Échec authentification Wazuh: %s", exc)
            raise RuntimeError(f"Échec de l'authentification Wazuh: {exc}") from exc

        token = response.text.strip().strip('"')

        if not token:
            logger.error("Token Wazuh vide")
            raise RuntimeError("Token Wazuh vide")

        self.token = token
        self.token_expire_at = time.time() + (15 * 60) - 30
        logger.debug("Token Wazuh obtenu")
        return token

    def _ensure_token(self) -> None:
        if self.auth_type == "token" and (
            not self.token or time.time() >= self.token_expire_at
        ):
            self.authenticate()

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }

        if self.auth_type == "token":
            self._ensure_token()
            headers["Authorization"] = f"Bearer {self.token}"

        return headers

    def _auth(self) -> Optional[HTTPBasicAuth]:
        if self.auth_type == "basic":
            return HTTPBasicAuth(self.username, self.password)
        return None

    def _build_url(self, endpoint: str) -> str:
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"
        return f"{self.base_url}{endpoint}"

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Response:
        url = self._build_url(endpoint)

        logger.debug(
            "Appel Wazuh %s %s params=%s json=%s",
            method,
            url,
            params or {},
            json or {},
        )

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self._headers(),
                params=params or {},
                json=json,
                auth=self._auth(),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )

            if response.status_code == 401 and self.auth_type == "token":
                logger.warning("401 reçu, renouvellement du token Wazuh")
                self.authenticate()
                response = requests.request(
                    method=method,
                    url=url,
                    headers=self._headers(),
                    params=params or {},
                    json=json,
                    auth=self._auth(),
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

            response.raise_for_status()
            return response

        except RequestException as exc:
            logger.error("Erreur appel Wazuh sur %s: %s", url, exc)
            raise RuntimeError(f"Erreur lors de l'appel Wazuh sur {url}: {exc}") from exc

    @staticmethod
    def _parse_json_response(response: Response, endpoint: str) -> Dict[str, Any]:
        if not response.text or not response.text.strip():
            logger.debug("Réponse vide reçue pour %s", endpoint)
            return {}

        try:
            return response.json()
        except ValueError as exc:
            logger.error("Réponse JSON invalide pour %s", endpoint)
            raise RuntimeError(f"Réponse JSON invalide renvoyée par Wazuh pour {endpoint}") from exc

    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        response = self._request("GET", endpoint, params=params)
        data = self._parse_json_response(response, endpoint)
        logger.debug("Réponse JSON Wazuh reçue pour %s", endpoint)
        return data

    def post(
        self,
        endpoint: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        response = self._request("POST", endpoint, params=params, json=json)
        data = self._parse_json_response(response, endpoint)
        logger.debug("Réponse JSON Wazuh reçue pour %s", endpoint)
        return data