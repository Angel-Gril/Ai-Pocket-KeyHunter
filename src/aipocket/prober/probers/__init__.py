"""Product-specific prober adapters.

Each module exports one :class:`~aipocket.prober.base.Prober` subclass that knows
how to fingerprint a product and which endpoints to read for credentials.
"""

from __future__ import annotations

from .dify import DifyProber
from .fastgpt import FastGPTProber
from .flowise import FlowiseProber
from .langflow import LangflowProber
from .librechat import LibreChatProber
from .litellm import LiteLLMProber
from .lobechat import LobeChatProber
from .newapi import NewAPIProber, OneAPIProber
from .openwebui import OpenWebUIProber

__all__ = [
    "DifyProber",
    "FastGPTProber",
    "FlowiseProber",
    "LangflowProber",
    "LobeChatProber",
    "LibreChatProber",
    "LiteLLMProber",
    "NewAPIProber",
    "OneAPIProber",
    "OpenWebUIProber",
]
