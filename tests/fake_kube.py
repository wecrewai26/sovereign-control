"""An in-memory Kubernetes API server for tests: just enough of pods, ReplicaSets and Deployments.

It models what the remediation tools rely on: controllers recreating deleted pods, Deployment
revisions kept as ReplicaSets, rollouts that only complete when the image is healthy and there
is capacity, and resourceVersion preconditions that reject concurrent writes with 409.
"""

import copy
import itertools
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOKEN = "sa-token"


def _merge(base, patch):
    for key, value in patch.items():
        if value is None:
            base.pop(key, None)
        elif isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def _template_key(template):
    t = copy.deepcopy(template)
    t.get("metadata", {}).get("labels", {}).pop("pod-template-hash", None)
    t.get("metadata", {}).pop("annotations", None)
    return json.dumps(t, sort_keys=True)


class Cluster:
    def __init__(self):
        self.lock = threading.Lock()
        self.ids = itertools.count(1)
        self.deployments, self.replicasets, self.pods = {}, {}, {}
        self.bad_images = set()
        self.capacity = 100  # pods the cluster can run per deployment
        self.concurrent_writer = False
        self.deleted = []
        self.events = {}
        self.logs = {}  # (ns, pod) -> text

    def uid(self):
        return f"uid-{next(self.ids)}"

    # -- setup --
    def add_deployment(self, ns, name, image, replicas=2, history=()):
        """Create a Deployment whose revisions are `history` images followed by `image`."""
        d = {"metadata": {"name": name, "namespace": ns, "uid": self.uid(), "generation": 1, "resourceVersion": "1",
                          "annotations": {}},
             "spec": {"replicas": replicas, "template": self._template(name, image)}, "status": {}}
        self.deployments[(ns, name)] = d
        for old in history:
            self._new_rs(d, self._template(name, old))
        self._rollout(d)
        return d

    def add_bare_pod(self, ns, name):
        self.pods[(ns, name)] = {"metadata": {"name": name, "namespace": ns, "uid": self.uid(),
                                              "creationTimestamp": "2026-10-01T00:00:00Z"},
                                 "spec": {"nodeName": "node-1", "containers": [{"name": name}]},
                                 "status": {"phase": "Running", "qosClass": "BestEffort", "containerStatuses": [
                                     {"name": name, "ready": True, "restartCount": 0, "state": {"running": {}}}]}}

    def evict(self, ns, name):
        pod = self.pods[(ns, name)]
        pod["status"].update(phase="Failed", reason="Evicted",
                             message="The node was low on resource: memory. Container x was using 2Gi.")
        for c in pod["status"]["containerStatuses"]:
            c.update(ready=False, state={"terminated": {"reason": "Error"}})

    def crashloop(self, ns, name, restarts=7):
        for c in self.pods[(ns, name)]["status"]["containerStatuses"]:
            c.update(ready=False, restartCount=restarts, state={"waiting": {"reason": "CrashLoopBackOff"}})

    def add_event(self, ns, name, kind, obj, reason, message, type_="Warning", count=1):
        self.events[(ns, name)] = {"metadata": {"name": name, "namespace": ns}, "type": type_, "reason": reason,
                                   "message": message, "count": count, "lastTimestamp": "2026-10-10T09:00:00Z",
                                   "involvedObject": {"kind": kind, "name": obj}}

    @staticmethod
    def _template(name, image):
        return {"metadata": {"labels": {"app": name}}, "spec": {"containers": [{"name": name, "image": image}]}}

    def _image(self, template):
        return template["spec"]["containers"][0]["image"]

    def _new_rs(self, d, template):
        revs = [int(r["metadata"]["annotations"]["deployment.kubernetes.io/revision"])
                for r in self._owned(d)] or [0]
        name = f"{d['metadata']['name']}-{next(self.ids)}"
        rs = {"metadata": {"name": name, "namespace": d["metadata"]["namespace"], "uid": self.uid(),
                           "annotations": {"deployment.kubernetes.io/revision": str(max(revs) + 1)},
                           "ownerReferences": [{"kind": "Deployment", "name": d["metadata"]["name"],
                                                "uid": d["metadata"]["uid"], "controller": True}]},
              "spec": {"template": _merge(copy.deepcopy(template),
                                          {"metadata": {"labels": {"pod-template-hash": name[-4:]}}})},
              "status": {}}
        self.replicasets[(rs["metadata"]["namespace"], name)] = rs
        return rs

    def _owned(self, d):
        return [r for r in self.replicasets.values()
                if r["metadata"]["ownerReferences"][0]["uid"] == d["metadata"]["uid"]]

    def _rollout(self, d):
        """Make the ReplicaSet for the current template current (reusing one, as Kubernetes does) and run pods."""
        key = _template_key(d["spec"]["template"])
        rs = next((r for r in self._owned(d) if _template_key(r["spec"]["template"]) == key), None)
        if rs is None:
            rs = self._new_rs(d, d["spec"]["template"])
        else:
            top = max(int(r["metadata"]["annotations"]["deployment.kubernetes.io/revision"]) for r in self._owned(d))
            if int(rs["metadata"]["annotations"]["deployment.kubernetes.io/revision"]) != top:
                rs["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = str(top + 1)
        d["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = \
            rs["metadata"]["annotations"]["deployment.kubernetes.io/revision"]
        ns = d["metadata"]["namespace"]
        for k in [k for k, p in self.pods.items() if k[0] == ns
                  and p["metadata"].get("ownerReferences", [{}])[0].get("name") in
                  {r["metadata"]["name"] for r in self._owned(d)}]:
            del self.pods[k]
        want = d["spec"]["replicas"]
        healthy = self._image(d["spec"]["template"]) not in self.bad_images
        available = min(want, self.capacity) if healthy else 0
        for _ in range(want):
            self._new_pod(rs, ready=healthy)
        rs["status"] = {"replicas": want, "readyReplicas": available}
        d["status"] = {"observedGeneration": d["metadata"]["generation"], "replicas": want,
                       "updatedReplicas": want, "availableReplicas": available, "readyReplicas": available}

    def _new_pod(self, rs, ready=True):
        name = f"{rs['metadata']['name']}-{next(self.ids)}"
        ns = rs["metadata"]["namespace"]
        app = rs["metadata"]["ownerReferences"][0]["name"]
        self.pods[(ns, name)] = {
            "metadata": {"name": name, "namespace": ns, "uid": self.uid(), "labels": {"app": rs["metadata"]["name"]},
                         "creationTimestamp": "2026-10-01T00:00:00Z",
                         "ownerReferences": [{"kind": "ReplicaSet", "name": rs["metadata"]["name"], "controller": True}]},
            "spec": {"nodeName": "node-1", "containers": [{"name": app}]},
            "status": {"phase": "Running", "qosClass": "Burstable", "containerStatuses": [
                {"name": app, "ready": ready, "restartCount": 0,
                 "state": {"running": {}} if ready else {"waiting": {"reason": "CrashLoopBackOff"}}}]}}

    def refresh_status(self, d):
        """Recount ready pods, as the Deployment controller does after pods change."""
        ready = sum(1 for p in self.pods_of(d["metadata"]["namespace"], d["metadata"]["name"])
                    if all(c["ready"] for c in p["status"]["containerStatuses"]))
        d["status"].update(availableReplicas=ready, readyReplicas=ready)

    def pods_of(self, ns, deployment):
        d = self.deployments[(ns, deployment)]
        names = {r["metadata"]["name"] for r in self._owned(d)}
        return [p for (n, _), p in self.pods.items() if n == ns
                and p["metadata"].get("ownerReferences", [{}])[0].get("name") in names]

    # -- writes --
    def write_deployment(self, ns, name, body, *, patch):
        d = self.deployments[(ns, name)]
        if self.concurrent_writer:  # someone else changed it between our read and write
            d["metadata"]["resourceVersion"] = str(int(d["metadata"]["resourceVersion"]) + 1)
            self.concurrent_writer = False
        rv = (body.get("metadata") or {}).get("resourceVersion")
        if rv is not None and rv != d["metadata"]["resourceVersion"]:
            return 409, {"message": "the object has been modified; please apply your changes to the latest version"}
        old_spec = json.dumps(d["spec"], sort_keys=True)
        if patch:
            body = copy.deepcopy(body)
            body.get("metadata", {}).pop("resourceVersion", None)
            _merge(d, body)
        else:
            d["spec"] = copy.deepcopy(body["spec"])
        d["metadata"]["resourceVersion"] = str(int(d["metadata"]["resourceVersion"]) + 1)
        if json.dumps(d["spec"], sort_keys=True) != old_spec:
            d["metadata"]["generation"] += 1
            self._rollout(d)
        return 200, d


class Handler(BaseHTTPRequestHandler):
    cluster: Cluster = None

    def _reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self):
        c = self.cluster
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._reply(401, {"message": "Unauthorized"})
        url = urlsplit(self.path)
        parts = url.path.strip("/").split("/")
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        with c.lock:
            # /api/v1/namespaces/{ns}/pods[/{name}]   /apis/apps/v1/namespaces/{ns}/{kind}[/{name}]
            offset = 2 if parts[0] == "api" else 3
            ns, kind = parts[offset + 1], parts[offset + 2]
            name = parts[offset + 3] if len(parts) > offset + 3 else None
            sub = parts[offset + 4] if len(parts) > offset + 4 else None
            if kind == "pods" and sub == "log" and self.command == "GET":
                if (ns, name) not in c.pods:
                    return self._reply(404, {"message": f'pods "{name}" not found'})
                tail = int(parse_qs(url.query).get("tailLines", ["200"])[0])
                text = "\n".join(c.logs.get((ns, name), "").splitlines()[-tail:]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(text)))
                self.end_headers()
                self.wfile.write(text)
                return
            store = {"pods": c.pods, "replicasets": c.replicasets, "deployments": c.deployments,
                     "events": c.events}.get(kind)
            if store is None:
                return self._reply(404, {"message": f"unknown resource {kind}"})
            if name is None and self.command == "GET":
                items = [o for (n, _), o in store.items() if n == ns]
                selector = parse_qs(url.query).get("labelSelector", [""])[0]
                if selector:
                    k, v = selector.split("=")
                    items = [o for o in items if o["metadata"].get("labels", {}).get(k) == v]
                return self._reply(200, {"items": items})
            obj = store.get((ns, name))
            if obj is None:
                return self._reply(404, {"message": f'{kind} "{name}" not found'})
            if self.command == "GET":
                return self._reply(200, obj)
            if self.command == "DELETE" and kind == "pods":
                expected = ((body or {}).get("preconditions") or {}).get("uid")
                if expected and expected != obj["metadata"]["uid"]:
                    return self._reply(409, {"message": "precondition failed: UID"})
                del c.pods[(ns, name)]
                c.deleted.append(name)
                refs = obj["metadata"].get("ownerReferences") or []
                if refs and refs[0]["kind"] == "ReplicaSet":
                    rs = c.replicasets[(ns, refs[0]["name"])]
                    d_name = rs["metadata"]["ownerReferences"][0]["name"]
                    d = c.deployments[(ns, d_name)]
                    c._new_pod(rs, ready=c._image(d["spec"]["template"]) not in c.bad_images)
                    c.refresh_status(d)
                return self._reply(200, {"status": "Success"})
            if kind == "deployments" and self.command in ("PATCH", "PUT"):
                code, result = c.write_deployment(ns, name, body, patch=self.command == "PATCH")
                return self._reply(code, result)
            return self._reply(405, {"message": "not supported"})

    do_GET = do_DELETE = do_PATCH = do_PUT = _handle

    def log_message(self, *args):
        pass


def start(cluster):
    handler = type("BoundHandler", (Handler,), {"cluster": cluster})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"
