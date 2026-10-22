# Threat Model

Net::UPnP is a Perl control-point library, not a server (lib/Net/UPnP.pm:81-92). UDP SSDP responses supply LOCATION, fetched by a custom IPv4 HTTP client to construct Device/Service objects (lib/Net/UPnP/ControlPoint.pm:55-120). Services resolve advertised endpoints and send SOAP (lib/Net/UPnP/Service.pm:127-249,266-323). AV wrappers browse metadata/control renderers; GW wrappers query and change port mappings. Optional dms2vodcast downloads/converts media through external Shell/curl/ffmpeg and writes RSS/files. CI only builds and runs a module-load test (.github/workflows/make.yml:6-32; t/UPnP.t:8-9).

## Assets

- Embedding process availability, memory and execution integrity; remote strings are buffered and parsed in-process (lib/Net/UPnP/HTTP.pm:105-145; lib/Net/UPnP/Device.pm:78-102; lib/Net/UPnP/ActionResponse.pm:98-120).
- Host outbound IPv4 TCP reachability for discovered descriptions and advertised SOAP endpoints (lib/Net/UPnP/ControlPoint.pm:85-100; lib/Net/UPnP/Service.pm:138-169,202-245; lib/Net/UPnP/HTTP.pm:86-100).
- Authorized SOAP operation structure, gateway mappings and renderer state (lib/Net/UPnP/Service.pm:217-245; lib/Net/UPnP/GW/Gateway.pm:194-209,240-248; lib/Net/UPnP/AV/MediaRenderer.pm:73-79,134-139).
- Conditional converter subprocess authority, account-accessible files, media outputs and RSS integrity (examples/dms2vodcast.pl:189-224,285-308).
- Local build/installation and CI runner integrity (README.md:19-24; Makefile.PL:3-17; Build.PL:3-18; .github/workflows/make.yml:24-32).

## Trust Boundaries

- Network peer -> discovery: default multicast destination 239.255.255.250:1900; st defaults upnp:rootdevice and mx defaults 3, overridable by globals/arguments. recv limits datagrams to 4096 bytes; each select waits mx*2. Sender identity is not retained, authenticated or compared with LOCATION (lib/Net/UPnP.pm:17-18; lib/Net/UPnP/ControlPoint.pm:30-35,55-100).
- LOCATION -> description GET: regex captures host/explicit port or 80/path, then inet_aton/connect uses caller network authority. No reply-origin/address-class restriction (lib/Net/UPnP/ControlPoint.pm:85-100; lib/Net/UPnP/HTTP.pm:86-100).
- Description -> future POST: absolute controlURL wins, else URLBase concatenation, else LOCATION-derived host/port. postaction/postquery parse the resolved endpoint and send SOAP; destination need not equal description origin (lib/Net/UPnP/Device.pm:51-55,78-102,251-253; lib/Net/UPnP/Service.pm:138-169,198-245,285-319).
- HTTP peer -> process: plaintext stream becomes status/headers and chunked, Content-Length or EOF body strings, returned as HTTPResponse. Framing does not impose aggregate size/read deadlines (lib/Net/UPnP/HTTP.pm:86-160).
- Caller operation and remote service metadata -> SOAP XML/header: application chooses authorized actions; no user/tenant authorization layer is supplied (lib/Net/UPnP/Service.pm:217-245,303-319).
- SOAP/DIDL -> objects: status 200 gates regex extraction/entity substitution, not device authentication. IDs, titles and URLs remain remote data; no general XML entity resolver (lib/Net/UPnP/ActionResponse.pm:98-120; lib/Net/UPnP/AV/MediaServer.pm:197-241).
- Optional converter metadata -> subprocess/files/RSS: URL from DIDL, filename from friendlyName+UDN+ID; UDN colons replaced, spaces removed, slashes replaced. MPEG2 staging <body>.mpeg is relative to CWD. MPEG4 uses raw base_directory+<body>_<ipod|psp>.m4v; existing output skips conversion, ffmpeg uses -y; executable lookup and exact Shell quoting remain external (examples/dms2vodcast.pl:6,103-119,272-308).
- RSS resource: raw base_directory+rss_file_name opened for output; raw rss_base_url+generated filename supplies links/enclosure; later publication is external (examples/dms2vodcast.pl:30-43,101-130,189-224).
- Gateway/rendering API -> external device: WANIPConnection/AVTransport wrappers check some service/status conditions; device authorization belongs to remote implementation (lib/Net/UPnP/GW/Gateway.pm:188-209,234-248; lib/Net/UPnP/AV/MediaRenderer.pm:70-79,131-139).
- CI executes checkout@v4 source on push/pull_request master/manual dispatch with ubuntu-latest, perl Makefile.PL and make test. No publication/deployment step (.github/workflows/make.yml:6-32).

## Attacker Capabilities

- Peer delivering UDP to discovery socket can supply SSDP LOCATION; plausible LAN prerequisite, no arbitrary Internet exposure assumed (lib/Net/UPnP/ControlPoint.pm:67-100).
- Advertised/compromised endpoint controls descriptions, service URLs, HTTP framing/body, SOAP/DIDL and media URLs (lib/Net/UPnP/ControlPoint.pm:100-113; lib/Net/UPnP/HTTP.pm:105-145; lib/Net/UPnP/AV/MediaServer.pm:197-241).
- Converter input reaches command option strings only when operator separately runs the example; exact Shell semantics need validation (examples/dms2vodcast.pl:6,272-308).
- No control of trusted account/CLI arguments/executables/CI credentials or device administration is assumed. Generic API invocation already within caller authority is not privilege gain.

## Security Objectives

- Bound duration, memory, counts and traversal for untrusted peers; discovery must terminate independently of peer activity.
- Prevent unauthenticated devices from exercising unintended outbound reachability; preserve caller-authorized SOAP structure (lib/Net/UPnP/ControlPoint.pm:85-100; lib/Net/UPnP/Service.pm:138-169,217-245).
- Converter must preserve execution/file/feed integrity while processing remote metadata, including CWD staging (examples/dms2vodcast.pl:189-224,285-308).
- Device-side gateway/renderer access policy is external; HTTP 200 and object construction do not authenticate peers.

## Assumptions

- No supplied deployment, tenants, credentials, production exposure or threat model. Generated model describes library and conditional examples.
- DEBUG defaults 0; globals/SetDebug permit caller changes. Socket/file/subprocess authority is inherited from caller (lib/Net/UPnP.pm:11-25).
- Local-network discovery documentation does not match a destination restriction: LOCATION accepts arbitrary matching HTTP hosts (lib/Net/UPnP/ControlPoint.pm:85-100,179-181).
- --base-directory documents RSS/MPEG4 placement; MPEG2 staging/deletion instead use CWD. Raw concatenation requires caller separator handling (examples/dms2vodcast.pl:31,43,103-104,189-191,289-308).
- Shell not vendored or found installed; Shell/curl/ffmpeg versions, PATH behavior and sandboxing unknown; build prerequisites only Test::More/version (examples/dms2vodcast.pl:6; Makefile.PL:11-14; Build.PL:11-14).
- No SECURITY.md resolved for root, lib, lib/Net, lib/Net/UPnP, AV, GW, examples, .github/workflows or t.
- Static offline review only; no runtime/exploit execution. Sole test checks module loading (t/UPnP.t:8-9).

---

## Saved Model Context

- Source: scan
- Scan: 2c7c7084-978d-4241-b23d-b28670a7edb9
- Target: cpan-net-upnp
- Revision: a1fa3ca1529eb361e777c397dee437c7e1e6a046
- Result status: completed
- Model origin: generated
- Model scope: .
- Model scope description: Whole current repository; independent architecture review verified against consumers.
- Scan scope: .
- Scan scope description: Offline Standard security review of all 33 current tracked repository files at a1fa3ca1529eb361e777c397dee437c7e1e6a046. Seven validated findings; coverage remains partial because the converter's external Shell execution boundary could not be resolved.
