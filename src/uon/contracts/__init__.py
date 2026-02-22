# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Strict Data Transfer Objects (DTO) interface boundary.

This module enforces the 'No Shared State' Modular Monolith philosophy.
Domains (e.g. ``uon.cli``, ``uon.auth``, ``uon.transport``) must never pass
raw primitives, dictionaries, or dynamically typed objects across
boundaries. Instead, all cross-domain parameters are strictly parsed,
validated, and transported natively via Pydantic V2 BaseModels.
"""

from .fido_dto import FidoAssertionDto, SecureEnvelopeDto

__all__ = [
    "FidoAssertionDto",
    "SecureEnvelopeDto",
]
