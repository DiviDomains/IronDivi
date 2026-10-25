//! UPnP port mapping (Divi Core's `-upnp`, ThreadMapPort, net.cpp:908-1007):
//! find the Internet gateway device, learn the external address (a local
//! address with LOCAL_UPNP under -discover), and map the listen port to this
//! host, refreshed every 20 minutes and removed at shutdown.
//!
//! The steps run against a [`PortMapper`]; [`Igd`] is the one that talks to
//! a gateway (SSDP discovery, then SOAP over HTTP), as miniupnpc does.

use crate::local::{LocalAddresses, LOCAL_UPNP};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::broadcast;
use tracing::info;

/// -upnp's default: off (DEFAULT_UPNP with USE_UPNP=0, net.cpp:67-71)
pub const DEFAULT_UPNP: bool = false;

/// How often the mapping is asked for again (net.cpp:968)
pub const REFRESH: Duration = Duration::from_secs(20 * 60);

/// A miniupnpc error code (UPNPCOMMAND_*, or the gateway's UPnPError code)
pub type UpnpError = i32;

/// UPNPCOMMAND_UNKNOWN_ERROR
pub const UNKNOWN_ERROR: UpnpError = -1;

/// The gateway operations ThreadMapPort uses
pub trait PortMapper: Send {
    /// UPNP_GetValidIGD: a gateway was found; this host's LAN address towards it
    fn find_gateway(&mut self) -> impl std::future::Future<Output = Option<IpAddr>> + Send;
    /// UPNP_GetExternalIPAddress (empty when the gateway gives none)
    fn external_ip(
        &mut self,
    ) -> impl std::future::Future<Output = Result<String, UpnpError>> + Send;
    /// UPNP_AddPortMapping of TCP `port` to `lan`:`port`, no lease limit
    fn add_port_mapping(
        &mut self,
        port: u16,
        lan: IpAddr,
        description: &str,
    ) -> impl std::future::Future<Output = Result<(), UpnpError>> + Send;
    /// UPNP_DeletePortMapping of TCP `port`
    fn delete_port_mapping(
        &mut self,
        port: u16,
    ) -> impl std::future::Future<Output = Result<(), UpnpError>> + Send;
}

/// ThreadMapPort: run until `shutdown`, then remove the mapping
pub async fn map_port<M: PortMapper>(
    mut mapper: M,
    local: Arc<LocalAddresses>,
    discover: bool,
    description: String,
    mut shutdown: broadcast::Receiver<()>,
) {
    let port = local.port();
    let Some(lan) = mapper.find_gateway().await else {
        info!("No valid UPnP IGDs found");
        return;
    };
    if discover {
        match mapper.external_ip().await {
            Err(r) => info!("UPnP: GetExternalIPAddress() returned {r}"),
            Ok(ip) if ip.is_empty() => info!("UPnP: GetExternalIPAddress failed."),
            Ok(ip) => {
                info!("UPnP: ExternalIPAddress = {ip}");
                // CNetAddr(text): an address that does not parse is 0.0.0.0,
                // which AddLocal does not take
                if let Ok(addr) = ip.parse::<IpAddr>() {
                    local.add(SocketAddr::new(addr, port), LOCAL_UPNP);
                }
            }
        }
    }
    loop {
        match mapper.add_port_mapping(port, lan, &description).await {
            Ok(()) => info!("UPnP Port Mapping successful."),
            Err(r) => info!("AddPortMapping({port}, {port}, {lan}) failed with code {r}"),
        }
        tokio::select! {
            _ = tokio::time::sleep(REFRESH) => {}
            _ = shutdown.recv() => break,
        }
    }
    let r = mapper.delete_port_mapping(port).await.err().unwrap_or(0);
    info!("UPNP_DeletePortMapping() returned : {r}");
}

/// A gateway's WAN connection service
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// http://host:port/path of the control endpoint
    pub control_url: String,
    /// urn:schemas-upnp-org:service:WANIPConnection:1 (or WANPPPConnection)
    pub service_type: String,
}

/// The Internet gateway device, found by SSDP (upnpDiscover, 2 s) or given
/// by its description URL
pub struct Igd {
    description_urls: Vec<String>,
    service: Option<Service>,
}

/// What M-SEARCH asks for, in miniupnpc's order
const SEARCH_TARGETS: [&str; 4] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "upnp:rootdevice",
];

const SSDP: &str = "239.255.255.250:1900";

impl Igd {
    /// Discover gateways by SSDP multicast on the LAN, for 2 seconds
    pub async fn discover() -> Self {
        let mut urls = Vec::new();
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
            for st in SEARCH_TARGETS {
                let msg = format!(
                    "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP}\r\nST: {st}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n"
                );
                let _ = socket.send_to(msg.as_bytes(), SSDP).await;
            }
            let deadline = tokio::time::Instant::now() + Duration::from_millis(2000);
            let mut buf = [0u8; 2048];
            while let Ok(Ok((n, _))) =
                tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
            {
                if let Some(url) = ssdp_location(&String::from_utf8_lossy(&buf[..n])) {
                    if !urls.contains(&url) {
                        urls.push(url);
                    }
                }
            }
        }
        Igd::at(urls)
    }

    /// Gateways by their description URLs
    pub fn at(description_urls: Vec<String>) -> Self {
        Igd {
            description_urls,
            service: None,
        }
    }

    async fn soap(&self, action: &str, args: &[(&str, String)]) -> Result<String, UpnpError> {
        let service = self.service.as_ref().ok_or(UNKNOWN_ERROR)?;
        let body_args: String = args
            .iter()
            .map(|(k, v)| format!("<{k}>{v}</{k}>"))
            .collect();
        let body = format!(
            "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{}\">{body_args}</u:{action}></s:Body></s:Envelope>\r\n",
            service.service_type
        );
        let soap_action = format!("\"{}#{action}\"", service.service_type);
        let (status, reply, _) = http(
            &service.control_url,
            "POST",
            &[
                ("Content-Type", "text/xml; charset=\"utf-8\""),
                ("SOAPAction", soap_action.as_str()),
            ],
            &body,
        )
        .await
        .ok_or(UNKNOWN_ERROR)?;
        if status == 200 {
            Ok(reply)
        } else {
            Err(xml_text(&reply, "errorCode")
                .and_then(|c| c.trim().parse().ok())
                .unwrap_or(UNKNOWN_ERROR))
        }
    }
}

impl PortMapper for Igd {
    async fn find_gateway(&mut self) -> Option<IpAddr> {
        for url in self.description_urls.clone() {
            let Some((200, xml, lan)) = http(&url, "GET", &[], "").await else {
                continue;
            };
            if let Some(service) = wan_service(&url, &xml) {
                self.service = Some(service);
                return Some(lan);
            }
        }
        None
    }

    async fn external_ip(&mut self) -> Result<String, UpnpError> {
        let reply = self.soap("GetExternalIPAddress", &[]).await?;
        Ok(xml_text(&reply, "NewExternalIPAddress").unwrap_or_default())
    }

    async fn add_port_mapping(
        &mut self,
        port: u16,
        lan: IpAddr,
        description: &str,
    ) -> Result<(), UpnpError> {
        self.soap(
            "AddPortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", port.to_string()),
                ("NewProtocol", "TCP".to_string()),
                ("NewInternalPort", port.to_string()),
                ("NewInternalClient", lan.to_string()),
                ("NewEnabled", "1".to_string()),
                ("NewPortMappingDescription", description.to_string()),
                ("NewLeaseDuration", "0".to_string()),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn delete_port_mapping(&mut self, port: u16) -> Result<(), UpnpError> {
        self.soap(
            "DeletePortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", port.to_string()),
                ("NewProtocol", "TCP".to_string()),
            ],
        )
        .await
        .map(|_| ())
    }
}

/// The LOCATION header of an SSDP reply
fn ssdp_location(reply: &str) -> Option<String> {
    reply.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("location")
            .then(|| v.trim().to_string())
    })
}

/// The text of the first `<tag>` element (namespace prefixes ignored)
fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let end = rest.find('>')?;
        let name = rest[..end].split_whitespace().next().unwrap_or("");
        let local = name.rsplit(':').next().unwrap_or(name);
        if local == tag && !name.starts_with('/') {
            let body = &rest[end + 1..];
            let close = body.find("</")?;
            return Some(body[..close].trim().to_string());
        }
        rest = &rest[end + 1..];
    }
    None
}

/// The WAN connection service of a device description, its control URL made
/// absolute against URLBase or the description's own URL (miniupnpc
/// parserootdesc / GetUPNPUrls)
fn wan_service(description_url: &str, xml: &str) -> Option<Service> {
    let base = xml_text(xml, "URLBase")
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| description_url.to_string());
    for kind in ["WANIPConnection", "WANPPPConnection"] {
        for block in xml.split("<service>").skip(1) {
            let block = block.split("</service>").next().unwrap_or("");
            let Some(st) = xml_text(block, "serviceType") else {
                continue;
            };
            if !st.contains(&format!(":service:{kind}:")) {
                continue;
            }
            let control = xml_text(block, "controlURL")?;
            return Some(Service {
                control_url: absolute_url(&base, &control),
                service_type: st,
            });
        }
    }
    None
}

fn absolute_url(base: &str, url: &str) -> String {
    if url.starts_with("http://") {
        return url.to_string();
    }
    let host_end = base
        .strip_prefix("http://")
        .and_then(|r| r.find('/').map(|i| i + 7))
        .unwrap_or(base.len());
    let root = &base[..host_end];
    if url.starts_with('/') {
        format!("{root}{url}")
    } else {
        format!("{root}/{url}")
    }
}

/// One HTTP/1.1 request to an http:// URL: status, body and this host's
/// address on the connection
async fn http(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Option<(u16, String, IpAddr)> {
    let rest = url.strip_prefix("http://")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let addr: SocketAddr = host
        .parse()
        .ok()
        .or_else(|| format!("{host}:80").parse().ok())?;
    let io = async {
        let mut s = TcpStream::connect(addr).await.ok()?;
        let lan = s.local_addr().ok()?.ip();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(body);
        s.write_all(req.as_bytes()).await.ok()?;
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).await.ok()?;
        let reply = String::from_utf8_lossy(&reply).into_owned();
        let status = reply.split_whitespace().nth(1)?.parse().ok()?;
        let body = reply
            .split_once("\r\n\r\n")
            .map_or("", |(_, b)| b)
            .to_string();
        Some((status, body, lan))
    };
    tokio::time::timeout(Duration::from_secs(5), io)
        .await
        .ok()?
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    /// A port mapper that records each call and answers as told
    #[derive(Clone, Default)]
    struct Stub {
        calls: Arc<Mutex<Vec<String>>>,
        gateway: Option<IpAddr>,
        external: Option<Result<String, UpnpError>>,
    }

    impl PortMapper for Stub {
        async fn find_gateway(&mut self) -> Option<IpAddr> {
            self.calls.lock().push("find_gateway".into());
            self.gateway
        }
        async fn external_ip(&mut self) -> Result<String, UpnpError> {
            self.calls.lock().push("external_ip".into());
            self.external.clone().unwrap_or(Err(UNKNOWN_ERROR))
        }
        async fn add_port_mapping(
            &mut self,
            port: u16,
            lan: IpAddr,
            description: &str,
        ) -> Result<(), UpnpError> {
            self.calls
                .lock()
                .push(format!("add {port} {lan} {description}"));
            Ok(())
        }
        async fn delete_port_mapping(&mut self, port: u16) -> Result<(), UpnpError> {
            self.calls.lock().push(format!("delete {port}"));
            Ok(())
        }
    }

    // The "external" address is only stored as a local address, never
    // contacted; Divi Core does not take the documentation ranges as local
    const EXTERNAL: &str = "11.22.33.44";

    fn lan() -> IpAddr {
        "192.168.1.20".parse().unwrap()
    }

    async fn run(stub: Stub, discover: bool) -> (Vec<String>, Vec<crate::local::LocalAddress>) {
        let local = Arc::new(LocalAddresses::new(true, discover, 51476));
        let (tx, rx) = broadcast::channel(1);
        let task = tokio::spawn(map_port(
            stub.clone(),
            Arc::clone(&local),
            discover,
            "DIVI test".into(),
            rx,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(());
        task.await.unwrap();
        let calls = stub.calls.lock().clone();
        (calls, local.list())
    }

    #[tokio::test]
    async fn maps_the_listen_port_and_unmaps_at_shutdown() {
        let stub = Stub {
            gateway: Some(lan()),
            external: Some(Ok(EXTERNAL.to_string())),
            ..Default::default()
        };
        let (calls, local) = run(stub, true).await;
        assert_eq!(
            calls,
            [
                "find_gateway",
                "external_ip",
                "add 51476 192.168.1.20 DIVI test",
                "delete 51476"
            ]
        );
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].address.to_string(), EXTERNAL);
        assert_eq!((local[0].port, local[0].score), (51476, LOCAL_UPNP));
    }

    #[tokio::test]
    async fn without_discover_the_external_address_is_not_asked() {
        let stub = Stub {
            gateway: Some(lan()),
            external: Some(Ok(EXTERNAL.to_string())),
            ..Default::default()
        };
        let (calls, local) = run(stub, false).await;
        assert_eq!(
            calls,
            [
                "find_gateway",
                "add 51476 192.168.1.20 DIVI test",
                "delete 51476"
            ]
        );
        assert!(local.is_empty());
    }

    #[tokio::test]
    async fn no_gateway_no_mapping() {
        let (calls, local) = run(Stub::default(), true).await;
        assert_eq!(calls, ["find_gateway"]);
        assert!(local.is_empty());
    }

    #[test]
    fn ssdp_location_header() {
        let reply = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(
            ssdp_location(reply).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
    }

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList><service>
<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<controlURL>/ctl/L3F</controlURL></service></serviceList>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL>
</service></serviceList></device></deviceList></device></deviceList>
</device></root>"#;

    #[test]
    fn description_gives_the_wan_service() {
        assert_eq!(
            wan_service("http://192.168.1.1:5000/rootDesc.xml", DESCRIPTION),
            Some(Service {
                control_url: "http://192.168.1.1:5000/ctl/IPConn".into(),
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
            })
        );
    }

    /// The Igd's HTTP and SOAP against a gateway stand-in on 127.0.0.1 (no
    /// SSDP: the description URL is given)
    #[tokio::test]
    async fn igd_speaks_soap_to_the_gateway() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Default::default();
        let record = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                // Read the headers and the body it announces
                loop {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&got).into_owned();
                record.lock().push(text.clone());
                let (status, body) = if text.starts_with("GET /rootDesc.xml") {
                    (200, DESCRIPTION.to_string())
                } else if text.contains("#GetExternalIPAddress") {
                    (200, "<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>11.22.33.44</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>".to_string())
                } else if text.contains("#AddPortMapping") {
                    (500, "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>".to_string())
                } else {
                    (200, "<s:Envelope/>".to_string())
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        let mut igd = Igd::at(vec![format!("http://{addr}/rootDesc.xml")]);
        assert_eq!(igd.find_gateway().await, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(
            igd.service.as_ref().unwrap().control_url,
            format!("http://{addr}/ctl/IPConn")
        );
        assert_eq!(igd.external_ip().await, Ok(EXTERNAL.to_string()));
        assert_eq!(
            igd.add_port_mapping(51476, lan(), "DIVI test").await,
            Err(718)
        );
        assert_eq!(igd.delete_port_mapping(51476).await, Ok(()));
        let got = seen.lock().clone();
        assert_eq!(got.len(), 4);
        assert!(got[1].contains(
            "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\""
        ));
        for part in [
            "<NewExternalPort>51476</NewExternalPort>",
            "<NewProtocol>TCP</NewProtocol>",
            "<NewInternalPort>51476</NewInternalPort>",
            "<NewInternalClient>192.168.1.20</NewInternalClient>",
            "<NewPortMappingDescription>DIVI test</NewPortMappingDescription>",
            "<NewLeaseDuration>0</NewLeaseDuration>",
        ] {
            assert!(got[2].contains(part), "{part}: {}", got[2]);
        }
        assert!(got[3].contains("#DeletePortMapping"));
    }
}
