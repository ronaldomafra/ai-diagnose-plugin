"""Lifecycle wiring for database, approval service, and local IPC."""

from __future__ import annotations

import os
from pathlib import Path

from diagnose.approval import ActionService
from diagnose.audit import AuditLog
from diagnose.config import (
    Configuration,
    database_path,
    default_endpoint_descriptor_path,
    default_unix_socket_path,
    load_configuration,
    resolve_ipc_endpoint,
)
from diagnose.ipc import (
    EndpointDescriptor,
    LocalIpcTransport,
    LoopbackTcpTransport,
    UnixDomainSocketTransport,
)
from diagnose.persistence import Database
from diagnose.sanitization import Sanitizer
from diagnose.terminal.service import TerminalService


class TerminalRuntime:
    """Own initialized resources and close them in a safe order."""

    def __init__(
        self,
        configuration: Configuration,
        database: Database,
        actions: ActionService,
        audit: AuditLog,
        service: TerminalService,
        transport: LocalIpcTransport,
        endpoint: EndpointDescriptor,
    ) -> None:
        self.configuration = configuration
        self.database = database
        self.actions = actions
        self.audit = audit
        self.service = service
        self.transport = transport
        self.endpoint = endpoint

    @classmethod
    async def start(
        cls,
        *,
        config_dir: str | Path | None = None,
        endpoint: str | Path | None = None,
    ) -> TerminalRuntime:
        configuration = load_configuration(config_dir)
        sanitizer = Sanitizer(
            sensitive_fields=configuration.settings.sensitive_fields,
            patterns=configuration.settings.redaction_patterns,
            max_output_bytes=configuration.settings.max_output_bytes,
            max_output_lines=configuration.settings.max_output_lines,
        )
        database = Database(database_path(configuration), sanitizer=sanitizer)
        await database.initialize()
        await database.reconcile_incomplete_actions()
        await database.expire_actions()

        audit = AuditLog(database, sanitizer=sanitizer)

        def configuration_provider() -> Configuration:
            return load_configuration(configuration.config_dir)

        actions = ActionService(
            database,
            configuration_provider,
            executors={},
            sanitizer=sanitizer,
            audit_log=audit,
        )
        service = TerminalService(
            database,
            configuration_provider,
            actions,
            audit,
            available_capabilities=set(),
        )
        explicit_endpoint = resolve_ipc_endpoint(
            str(endpoint) if endpoint is not None else None,
            settings=configuration.settings,
        )
        if os.name == "nt":
            descriptor_path = (
                Path(explicit_endpoint) if explicit_endpoint else default_endpoint_descriptor_path()
            )
            transport: LocalIpcTransport = LoopbackTcpTransport(descriptor_path)
        else:
            socket_path = (
                Path(explicit_endpoint) if explicit_endpoint else default_unix_socket_path()
            )
            transport = UnixDomainSocketTransport(socket_path)
        descriptor = await transport.start(service.handle)
        service.endpoint = descriptor
        await audit.append(
            "server.started",
            data={
                "protocolVersion": descriptor.protocol_version,
                "transport": descriptor.transport.value,
                "targetCount": len(configuration.targets),
                "policyCount": len(configuration.policy_set.policies),
            },
        )
        return cls(configuration, database, actions, audit, service, transport, descriptor)

    async def close(self) -> None:
        await self.audit.append("server.stopped")
        await self.actions.close()
        await self.transport.close()
        await self.database.close()
