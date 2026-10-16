use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wgmesh_coord::{config, load_tls, serve};

fn config_file(dir: &std::path::Path, tls: serde_json::Value) -> config::Config {
    let mut value = serde_json::json!({
        "mesh_cidr": "10.42.0.0/16", "state_path": "unused", "authorized_signers": "unused"
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(tls.as_object().unwrap().clone());
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    config::load(path.to_str().unwrap()).unwrap()
}

#[tokio::test]
async fn configured_certificate_serves_real_https_and_rejects_plain_http() {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let cfg = config_file(
        dir.path(),
        serde_json::json!({"tls_cert": cert_path, "tls_key": key_path}),
    );
    let tls = load_tls(&cfg).await.unwrap();
    let tls_handle = tls.as_ref().unwrap().clone();
    let renewed = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = axum_server::Handle::new();
    let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
    let server = tokio::spawn(serve(listener, app, tls, handle.clone()));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    roots.add(renewed.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client));
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stream = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok"), "{response}");
    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    plain
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut bytes = [0; 256];
    let result = tokio::time::timeout(Duration::from_secs(5), plain.read(&mut bytes))
        .await
        .unwrap();
    assert!(result.is_err() || !String::from_utf8_lossy(&bytes).contains("200 OK"));
    // SIGHUP uses this same reload helper; the live listener must present
    // the renewed certificate without restarting or touching peer state.
    std::fs::write(&cert_path, renewed.cert.pem()).unwrap();
    std::fs::write(&key_path, renewed.key_pair.serialize_pem()).unwrap();
    wgmesh_coord::reload_tls(&tls_handle, &cfg).await.unwrap();
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let renewed_stream = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    assert_eq!(
        &renewed_stream.get_ref().1.peer_certificates().unwrap()[0],
        renewed.cert.der()
    );
    drop(renewed_stream);
    std::fs::write(&key_path, "invalid renewal key").unwrap();
    assert!(wgmesh_coord::reload_tls(&tls_handle, &cfg).await.is_err());
    let socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let retained = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    assert_eq!(
        &retained.get_ref().1.peer_certificates().unwrap()[0],
        renewed.cert.der()
    );
    drop(retained);
    handle.shutdown();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn incomplete_or_unreadable_tls_configuration_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    for tls in [
        serde_json::json!({"tls_cert": "missing"}),
        serde_json::json!({"tls_key": "missing"}),
        serde_json::json!({"tls_cert": "missing", "tls_key": "missing"}),
    ] {
        assert!(load_tls(&config_file(dir.path(), tls)).await.is_err());
    }
    assert!(load_tls(&config_file(dir.path(), serde_json::json!({})))
        .await
        .unwrap()
        .is_none());
}
