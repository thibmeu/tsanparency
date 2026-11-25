using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [(name = "main", worker = (
    modules = [(name = "worker", esModule = embed ".trace/worker.js")],
    compatibilityDate = "2026-08-01",
  ))],
  sockets = [(name = "http", address = "127.0.0.1:8789", http = (), service = "main")],
);
