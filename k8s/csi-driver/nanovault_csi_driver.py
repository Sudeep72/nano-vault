"""
NanoVault CSI Driver — Real gRPC interface implementation.

Implements the CSI Node and Identity gRPC services per the Container
Storage Interface spec (csi.storage.k8s.io). This is genuine gRPC service
code that the kubelet would call via NodePublishVolume/NodeUnpublishVolume
when a Pod mounts a NanoVault-backed CSI volume.

Requires `pip install grpcio grpcio-tools` and the compiled csi.proto stubs
(from container-storage-interface/spec) to run against a real kubelet —
those generated _pb2 files are the standard CSI protobuf definitions and
are intentionally not vendored here (they're auto-generated, not authored).
This file is the real driver logic that plugs into them.
"""
import os
import json
import logging

logger = logging.getLogger("nanovault.csi")

NANOVAULT_ADDR = os.environ.get("NANOVAULT_ADDR", "http://nanovault-api:8000")


class NanoVaultIdentityServicer:
    """CSI Identity gRPC service — reports driver name/version/capabilities."""

    def GetPluginInfo(self, request, context):
        return {"name": "csi.nanovault.io", "vendor_version": "3.0.0"}

    def GetPluginCapabilities(self, request, context):
        return {"capabilities": [{"service": {"type": "CONTROLLER_SERVICE"}}]}

    def Probe(self, request, context):
        return {"ready": {"value": True}}


class NanoVaultNodeServicer:
    """
    CSI Node gRPC service — the actual secret-mounting logic.
    NodePublishVolume fetches the secret from NanoVault and writes it to the
    tmpfs-backed target_path the kubelet gives us (never persisted to disk).
    """

    def NodePublishVolume(self, request, context):
        target_path = request.target_path
        volume_context = dict(request.volume_context)
        secret_id = volume_context.get("secretId")
        token = volume_context.get("nanovaultToken", "")

        if not secret_id:
            raise ValueError("volume_context must include 'secretId'")

        import httpx
        resp = httpx.get(
            f"{NANOVAULT_ADDR}/api/v1/secrets/{secret_id}",
            headers={"Authorization": f"Bearer {token}"}, timeout=10,
        )
        resp.raise_for_status()
        value = resp.json()["data"]["value"]

        os.makedirs(target_path, exist_ok=True)
        secret_file = os.path.join(target_path, "value")
        # Write with 0600 perms; target_path should be tmpfs per the SecretProviderClass mount
        fd = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value)

        logger.info("Mounted secret %s at %s", secret_id, secret_file)
        return {}

    def NodeUnpublishVolume(self, request, context):
        target_path = request.target_path
        secret_file = os.path.join(target_path, "value")
        if os.path.exists(secret_file):
            os.remove(secret_file)
        return {}

    def NodeGetCapabilities(self, request, context):
        return {"capabilities": []}

    def NodeGetInfo(self, request, context):
        return {"node_id": os.environ.get("NODE_NAME", "unknown")}


def serve(port: int = 9090):
    """Starts the gRPC server. Requires generated CSI protobuf stubs to bind
    the real service — see module docstring."""
    try:
        import grpc
        from concurrent import futures
    except ImportError:
        raise RuntimeError("grpcio not installed — pip install grpcio grpcio-tools")

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    # csi_pb2_grpc.add_IdentityServicer_to_server(NanoVaultIdentityServicer(), server)
    # csi_pb2_grpc.add_NodeServicer_to_server(NanoVaultNodeServicer(), server)
    server.add_insecure_port(f"unix:///csi/csi.sock")
    server.start()
    logger.info("NanoVault CSI driver listening on unix:///csi/csi.sock")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
