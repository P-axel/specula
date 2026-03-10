from typing import Any, Dict, Optional

import requests
from requests import Response
from requests.exceptions import RequestException

from config.settings import settings


class WazuhClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
    ) -> None:
        self.base_url = (base_url or settings.wazuh_base_url).rstrip("/")
        self.username = username or settings.wazuh_username
        self.password = password or settings.wazuh_password
        self.verify_ssl = verify_ssl if verify_ssl is not None else settings.wazuh_verify_tls
        self.timeout = timeout if timeout is not None else settings.wazuh_timeout

        self.token: Optional[str] = None

        if not self.base_url:
            raise ValueError("WAZUH_BASE_URL manquant")
        if not self.username:
            raise ValueError("WAZUH_USERNAME manquant")
        if not self.password:
            raise ValueError("WAZUH_PASSWORD manquant")

    def authenticate(self) -> str:
        url = f"{self.base_url}/security/user/authenticate"
        params = {"raw": "true"}

        try:
            response = requests.post(
                url,
                params=params,
                auth=(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            response.raise_for_status()

        except RequestException as exc:
            raise RuntimeError(f"Échec de l'authentification Wazuh: {exc}") from exc

        token = response.text.strip().strip('"')

        if not token:
            raise RuntimeError("Token Wazuh vide")

        self.token = token
        return token

    def _headers(self) -> Dict[str, str]:
        if not self.token:
            self.authenticate()

        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _build_url(self, endpoint: str) -> str:
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"

        return f"{self.base_url}{endpoint}"

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Response:
        url = self._build_url(endpoint)

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self._headers(),
                params=params or {},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )

            if response.status_code == 401:
                self.authenticate()

                response = requests.request(
                    method=method,
                    url=url,
                    headers=self._headers(),
                    params=params or {},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

            response.raise_for_status()
            return response

        except RequestException as exc:
            raise RuntimeError(f"Erreur lors de l'appel Wazuh sur {url}: {exc}") from exc

    def get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        response = self._request("GET", endpoint, params=params)

        try:
            return response.json()

        except ValueError as exc:
            raise RuntimeError("Réponse JSON invalide renvoyée par Wazuh") from exc