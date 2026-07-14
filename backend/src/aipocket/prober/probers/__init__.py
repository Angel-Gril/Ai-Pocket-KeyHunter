"""Product-specific prober adapters.

Each module exports one :class:`~aipocket.prober.base.Prober` subclass that knows
how to fingerprint a product and which audited ProbeSpecs to run.
"""

from __future__ import annotations

from .anythingllm import AnythingLLMProber
from .chatgpt_next_web import ChatGPTNextWebProber
from .dify import DifyProber
from .fastgpt import FastGPTProber
from .flowise import FlowiseProber
from .generic import GenericPageProber
from .langflow import LangflowProber
from .librechat import LibreChatProber
from .litellm import LiteLLMProber
from .lobechat import LobeChatProber
from .newapi import NewAPIProber, OneAPIProber
from .openrouter import OpenRouterProber
from .openwebui import OpenWebUIProber
from .portkey import PortkeyProber

__all__ = [
    "AnythingLLMProber",
    "ChatGPTNextWebProber",
    "DifyProber",
    "FastGPTProber",
    "FlowiseProber",
    "GenericPageProber",
    "LangflowProber",
    "LobeChatProber",
    "LibreChatProber",
    "LiteLLMProber",
    "NewAPIProber",
    "OneAPIProber",
    "OpenRouterProber",
    "OpenWebUIProber",
    "PortkeyProber",
]
