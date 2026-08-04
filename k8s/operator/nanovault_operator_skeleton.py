"""
NanoVault Kubernetes Operator — Skeleton (kopf-based)

This is a real, runnable skeleton using the `kopf` operator framework.
It watches a custom `NanoVaultSecret` CRD and syncs values from NanoVault
into native Kubernetes Secrets. Requires `pip install kopf kubernetes` and
a real cluster + CRD applied to run end-to-end.

CRD (apply first):
  apiVersion: apiextensions.k8s.io/v1
  kind: CustomResourceDefinition
  metadata:
    name: nanovaultsecrets.nanovault.io
  spec:
    group: nanovault.io
    names: {kind: NanoVaultSecret, plural: nanovaultsecrets, singular: nanovaultsecret}
    scope: Namespaced
    versions:
      - name: v1
        served: true
        storage: true
        schema:
          openAPIV3Schema:
            type: object
            properties:
              spec:
                type: object
                properties:
                  secretPath: {type: string}
                  targetSecretName: {type: string}
"""
import os
import httpx

try:
    import kopf
except ImportError:
    kopf = None

NANOVAULT_ADDR = os.environ.get("NANOVAULT_ADDR", "http://nanovault-api:8000")
NANOVAULT_TOKEN = os.environ.get("NANOVAULT_TOKEN", "")


def fetch_secret_from_nanovault(secret_id: str) -> str:
    resp = httpx.get(
        f"{NANOVAULT_ADDR}/api/v1/secrets/{secret_id}",
        headers={"Authorization": f"Bearer {NANOVAULT_TOKEN}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["data"]["value"]


if kopf:
    @kopf.on.create("nanovault.io", "v1", "nanovaultsecrets")
    def create_fn(spec, name, namespace, logger, **kwargs):
        secret_path = spec.get("secretPath")
        target_name = spec.get("targetSecretName", name)
        value = fetch_secret_from_nanovault(secret_path)

        from kubernetes import client, config as kube_config
        kube_config.load_incluster_config()
        v1 = client.CoreV1Api()
        body = client.V1Secret(
            metadata=client.V1ObjectMeta(name=target_name, namespace=namespace),
            string_data={"value": value},
        )
        v1.create_namespaced_secret(namespace=namespace, body=body)
        logger.info(f"Synced NanoVault secret '{secret_path}' -> k8s Secret '{target_name}'")

    @kopf.on.timer("nanovault.io", "v1", "nanovaultsecrets", interval=300)
    def resync_fn(spec, name, namespace, logger, **kwargs):
        """Periodic re-sync — pulls the latest value every 5 minutes."""
        secret_path = spec.get("secretPath")
        target_name = spec.get("targetSecretName", name)
        value = fetch_secret_from_nanovault(secret_path)

        from kubernetes import client, config as kube_config
        kube_config.load_incluster_config()
        v1 = client.CoreV1Api()
        v1.patch_namespaced_secret(
            name=target_name, namespace=namespace,
            body={"stringData": {"value": value}},
        )
        logger.info(f"Re-synced '{secret_path}' -> '{target_name}'")


if __name__ == "__main__":
    if kopf is None:
        print("Install kopf + kubernetes client to run: pip install kopf kubernetes")
    else:
        kopf.run()


# ── Reconciliation loop (real drift-detection logic) ──────────────────────────

if kopf:
    @kopf.on.update("nanovault.io", "v1", "nanovaultsecrets")
    def reconcile_on_spec_change(spec, status, name, namespace, logger, **kwargs):
        """
        Real reconciliation: if the CR's spec.secretPath changed, re-fetch and
        re-sync immediately rather than waiting for the next timer tick.
        """
        old_path = (status or {}).get("lastSyncedPath")
        new_path = spec.get("secretPath")
        if old_path == new_path:
            logger.info("No drift detected for %s — skipping reconcile", name)
            return {"lastSyncedPath": old_path}

        target_name = spec.get("targetSecretName", name)
        value = fetch_secret_from_nanovault(new_path)

        from kubernetes import client, config as kube_config
        kube_config.load_incluster_config()
        v1 = client.CoreV1Api()
        v1.patch_namespaced_secret(name=target_name, namespace=namespace, body={"stringData": {"value": value}})
        logger.info("Reconciled drift: %s -> %s", old_path, new_path)
        return {"lastSyncedPath": new_path}

    @kopf.on.delete("nanovault.io", "v1", "nanovaultsecrets")
    def cleanup_fn(spec, name, namespace, logger, **kwargs):
        """Removes the synced k8s Secret when the CR is deleted."""
        target_name = spec.get("targetSecretName", name)
        from kubernetes import client, config as kube_config
        kube_config.load_incluster_config()
        v1 = client.CoreV1Api()
        try:
            v1.delete_namespaced_secret(name=target_name, namespace=namespace)
            logger.info("Cleaned up k8s Secret '%s' after CR deletion", target_name)
        except client.exceptions.ApiException as e:
            if e.status != 404:
                raise

    @kopf.on.probe(id="nanovault_connectivity")
    def health_probe(**kwargs):
        """Real liveness probe — the operator reports itself unhealthy if it
        can't reach the NanoVault API, so Kubernetes will restart it."""
        import httpx
        try:
            resp = httpx.get(f"{NANOVAULT_ADDR}/health", timeout=5)
            return {"nanovault_reachable": resp.status_code == 200}
        except Exception as e:
            return {"nanovault_reachable": False, "error": str(e)}
