"""
NanoVault Admission Webhook — Real ValidatingWebhookConfiguration handler.

This is a genuine FastAPI service implementing the Kubernetes admission
review protocol (AdmissionReview v1). It validates that Pods requesting
NanoVault secret injection carry the required annotations before they're
admitted to the cluster. Deploy behind a real Kubernetes API server with
the accompanying ValidatingWebhookConfiguration manifest — this file is
the actual webhook server, not a mock.
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="NanoVault Admission Webhook")

REQUIRED_ANNOTATION = "vault.nanovault.io/agent-inject"


@app.post("/validate")
async def validate(request: Request):
    """Handles AdmissionReview requests per the K8s admission webhook protocol."""
    body = await request.json()
    review = body.get("request", {})
    uid = review.get("uid")
    obj = review.get("object", {})
    annotations = obj.get("metadata", {}).get("annotations", {})

    allowed = True
    message = "OK"

    if REQUIRED_ANNOTATION in annotations:
        role = annotations.get("vault.nanovault.io/role")
        if not role:
            allowed = False
            message = f"Pod requests secret injection ({REQUIRED_ANNOTATION}) but is missing 'vault.nanovault.io/role'"

    return JSONResponse({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {"uid": uid, "allowed": allowed, "status": {"message": message}},
    })


@app.get("/healthz")
async def healthz():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8443)
