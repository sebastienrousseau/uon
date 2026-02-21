"""Utility helpers -- configuration, path discovery, and data containers.

This package provides the ``Target`` data model and ``TargetStore``
persistence layer used by every other uon sub-system.  Configuration is
stored as plain JSON under a platform-appropriate directory (see
``config._config_dir()``); no secret material is ever written to disk.
"""
