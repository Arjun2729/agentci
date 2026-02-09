"""Monkey-patches for Python network operations (urllib, http.client)."""

from __future__ import annotations

import http.client
import urllib.request
from typing import Any
from urllib.parse import urlparse

from agentci_recorder.canonicalize import to_etld_plus1
from agentci_recorder.logger import logger
from agentci_recorder.types import EffectEventData, NetEffectData, effect_data_to_dict, make_event

_original_urlopen = urllib.request.urlopen
_original_http_request = http.client.HTTPConnection.request
_original_https_request = http.client.HTTPSConnection.request
_original_requests_request: Any = None


def _record_net(ctx: dict[str, Any], protocol: str, host: str, method: str, port: int | None = None) -> None:
    try:
        data = EffectEventData(
            category="net_outbound",
            kind="observed",
            net=NetEffectData(
                host_raw=host,
                host_etld_plus_1=to_etld_plus1(host),
                method=method.upper(),
                protocol=protocol,  # type: ignore[arg-type]
                port=port,
            ),
        )
        ctx["writer"].write(
            make_event(ctx["run_id"], "effect", effect_data_to_dict(data))
        )
    except Exception as e:
        logger.debug(f"Failed to record network effect: {e}")


def patch_network(ctx: dict[str, Any]) -> None:
    """Patch urllib.request.urlopen and http.client connections."""

    def patched_urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:
        if not ctx["state"]["bypass"]:
            try:
                url_str = url if isinstance(url, str) else getattr(url, "full_url", str(url))
                parsed = urlparse(url_str)
                host = parsed.hostname or ""
                protocol = "https" if parsed.scheme == "https" else "http"
                method = getattr(url, "get_method", lambda: "GET")()
                _record_net(ctx, protocol, host, method, parsed.port)
            except Exception as e:
                logger.debug(f"Failed to extract URL info: {e}")
        return _original_urlopen(url, *args, **kwargs)

    def patched_http_request(
        self: http.client.HTTPConnection, method: str, url: str, *args: Any, **kwargs: Any
    ) -> Any:
        if not ctx["state"]["bypass"]:
            host = self.host or ""
            protocol = "https" if isinstance(self, http.client.HTTPSConnection) else "http"
            port = getattr(self, "port", None)
            _record_net(ctx, protocol, host, method, port)
        return _original_http_request(self, method, url, *args, **kwargs)

    def patched_https_request(
        self: http.client.HTTPSConnection, method: str, url: str, *args: Any, **kwargs: Any
    ) -> Any:
        if not ctx["state"]["bypass"]:
            host = self.host or ""
            port = getattr(self, "port", None)
            _record_net(ctx, "https", host, method, port)
        return _original_https_request(self, method, url, *args, **kwargs)

    urllib.request.urlopen = patched_urlopen  # type: ignore[assignment]
    http.client.HTTPConnection.request = patched_http_request  # type: ignore[assignment]
    http.client.HTTPSConnection.request = patched_https_request  # type: ignore[assignment]

    # Optional: patch requests if installed
    try:
        import requests  # type: ignore

        global _original_requests_request
        _original_requests_request = requests.sessions.Session.request

        def patched_requests_request(self, method: str, url: str, *args: Any, **kwargs: Any) -> Any:  # type: ignore[no-untyped-def]
            if not ctx["state"]["bypass"]:
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or ""
                    protocol = "https" if parsed.scheme == "https" else "http"
                    _record_net(ctx, protocol, host, method, parsed.port)
                except Exception as e:
                    logger.debug(f"Failed to extract requests URL info: {e}")
            return _original_requests_request(self, method, url, *args, **kwargs)

        requests.sessions.Session.request = patched_requests_request  # type: ignore[assignment]
    except Exception:
        pass


def unpatch_network() -> None:
    urllib.request.urlopen = _original_urlopen  # type: ignore[assignment]
    http.client.HTTPConnection.request = _original_http_request  # type: ignore[assignment]
    http.client.HTTPSConnection.request = _original_https_request  # type: ignore[assignment]
    if _original_requests_request is not None:
        try:
            import requests  # type: ignore

            requests.sessions.Session.request = _original_requests_request  # type: ignore[assignment]
        except Exception:
            pass
