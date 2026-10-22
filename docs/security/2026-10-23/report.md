# Security Review: cpan-net-upnp

## Scope

Offline Standard security review of all 33 current tracked repository files at a1fa3ca1529eb361e777c397dee437c7e1e6a046. Seven validated findings; coverage remains partial because the converter's external Shell execution boundary could not be resolved.

- Scan mode: repository
- Target kind: git_revision
- Target ID: target_sha256_8e03122cde13d97a762ce13ca453385e11accdddaa9d6c935791096b8c36241d
- Revision: a1fa3ca1529eb361e777c397dee437c7e1e6a046
- Inventory strategy: repository
- Included paths: .
- Excluded paths: none
- Artifacts reviewed: Warning: truncated output (original token count: 2376), Total output lines: 54, .github/workflows/make.yml, .gitignore, AUTHORS, Build.PL, Changes, MANIFEST, META.json, META.yml, Makefile.PL, README.md, examples/dms2vodcast.pl, examples/upnpavchk.pl, examples/upnpavdump.pl, examples/upnpavsimple.pl, examples/upnpchk.pl, examples/upnpdump.pl, examples/upnpgwdump.pl, examples/upnpgwtool.pl, lib/Net/UPnP.pm, lib/Net/UPnP/AV/Container.pm, lib/Net/UPnP/AV/Content.pm, lib/Net/UPnP/AV/Item.pm, lib/Net/UPnP/AV/MediaRenderer.pm, lib/Net/UPnP/AV/MediaServer.pm, lib/Net/UPnP/ActionResponse.pm, lib/Net/UPnP/ControlPoint.pm, lib/Net/UPnP/Device.pm, lib/Net/UPnP/GW/Gateway.pm, lib/Net/UPnP/HTTP.pm, lib/Net/UPnP/HTTPResponse.pm, lib/Net/UPnP/QueryResponse.pm
- Scan context: User requested repository review and a PR containing the results. Generated independent architecture model verified against local consumers; independent baseline plus focused investigation within a four-thread session.

Limitations and exclusions:
- Only authorized current source inspected offline; no history, external advisory lookup, live deployment or dependency installation.
- All 33 repository files reviewed; installed Shell.pm unavailable, so suspected command execution remains deferred and is not counted among findings.
- No production exposure or specific privileged loopback target established.
- Preflight ready with warning: four total runtime slots rather than suggested six; independent baseline and focused investigation completed.
- Token usage measurement unavailable from this prompt-driven scan.

### Scan Summary

| Field | Value |
| --- | --- |
| Scan outcome | completed |
| Reportable findings | 7 |
| Severity mix | medium: 5, low: 2 |
| Confidence mix | high: 7 |
| Coverage | partial |
| Validation mode | static source trace |

Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.

## Threat Model

Net::UPnP is a Perl control-point library, not a server (lib/Net/UPnP.pm:81-92). UDP SSDP responses supply LOCATION, fetched by a custom IPv4 HTTP client to construct Device/Service objects (lib/Net/UPnP/ControlPoint.pm:55-120). Services resolve advertised endpoints and send SOAP (lib/Net/UPnP/Service.pm:127-249,266-323). AV wrappers browse metadata/control renderers; GW wrappers query and change port mappings. Optional dms2vodcast downloads/converts media through external Shell/curl/ffmpeg and writes RSS/files. CI only builds and runs a module-load test (.github/workflows/make.yml:6-32; t/UPnP.t:8-9).

### Assets

- Embedding process availability, memory and execution integrity; remote strings are buffered and parsed in-process (lib/Net/UPnP/HTTP.pm:105-145; lib/Net/UPnP/Device.pm:78-102; lib/Net/UPnP/ActionResponse.pm:98-120).
- Host outbound IPv4 TCP reachability for discovered descriptions and advertised SOAP endpoints (lib/Net/UPnP/ControlPoint.pm:85-100; lib/Net/UPnP/Service.pm:138-169,202-245; lib/Net/UPnP/HTTP.pm:86-100).
- Authorized SOAP operation structure, gateway mappings and renderer state (lib/Net/UPnP/Service.pm:217-245; lib/Net/UPnP/GW/Gateway.pm:194-209,240-248; lib/Net/UPnP/AV/MediaRenderer.pm:73-79,134-139).
- Conditional converter subprocess authority, account-accessible files, media outputs and RSS integrity (examples/dms2vodcast.pl:189-224,285-308).
- Local build/installation and CI runner integrity (README.md:19-24; Makefile.PL:3-17; Build.PL:3-18; .github/workflows/make.yml:24-32).

### Trust Boundaries

- Network peer -\> discovery: default multicast destination 239.255.255.250:1900; st defaults upnp:rootdevice and mx defaults 3, overridable by globals/arguments. recv limits datagrams to 4096 bytes; each select waits mx\*2. Sender identity is not retained, authenticated or compared with LOCATION (lib/Net/UPnP.pm:17-18; lib/Net/UPnP/ControlPoint.pm:30-35,55-100).
- LOCATION -\> description GET: regex captures host/explicit port or 80/path, then inet_aton/connect uses caller network authority. No reply-origin/address-class restriction (lib/Net/UPnP/ControlPoint.pm:85-100; lib/Net/UPnP/HTTP.pm:86-100).
- Description -\> future POST: absolute controlURL wins, else URLBase concatenation, else LOCATION-derived host/port. postaction/postquery parse the resolved endpoint and send SOAP; destination need not equal description origin (lib/Net/UPnP/Device.pm:51-55,78-102,251-253; lib/Net/UPnP/Service.pm:138-169,198-245,285-319).
- HTTP peer -\> process: plaintext stream becomes status/headers and chunked, Content-Length or EOF body strings, returned as HTTPResponse. Framing does not impose aggregate size/read deadlines (lib/Net/UPnP/HTTP.pm:86-160).
- Caller operation and remote service metadata -\> SOAP XML/header: application chooses authorized actions; no user/tenant authorization layer is supplied (lib/Net/UPnP/Service.pm:217-245,303-319).
- SOAP/DIDL -\> objects: status 200 gates regex extraction/entity substitution, not device authentication. IDs, titles and URLs remain remote data; no general XML entity resolver (lib/Net/UPnP/ActionResponse.pm:98-120; lib/Net/UPnP/AV/MediaServer.pm:197-241).
- Optional converter metadata -\> subprocess/files/RSS: URL from DIDL, filename from friendlyName+UDN+ID; UDN colons replaced, spaces removed, slashes replaced. MPEG2 staging \<body\>.mpeg is relative to CWD. MPEG4 uses raw base_directory+\<body\>_\<ipod|psp\>.m4v; existing output skips conversion, ffmpeg uses -y; executable lookup and exact Shell quoting remain external (examples/dms2vodcast.pl:6,103-119,272-308).
- RSS resource: raw base_directory+rss_file_name opened for output; raw rss_base_url+generated filename supplies links/enclosure; later publication is external (examples/dms2vodcast.pl:30-43,101-130,189-224).
- Gateway/rendering API -\> external device: WANIPConnection/AVTransport wrappers check some service/status conditions; device authorization belongs to remote implementation (lib/Net/UPnP/GW/Gateway.pm:188-209,234-248; lib/Net/UPnP/AV/MediaRenderer.pm:70-79,131-139).
- CI executes checkout@v4 source on push/pull_request master/manual dispatch with ubuntu-latest, perl Makefile.PL and make test. No publication/deployment step (.github/workflows/make.yml:6-32).

### Attacker Capabilities

- Peer delivering UDP to discovery socket can supply SSDP LOCATION; plausible LAN prerequisite, no arbitrary Internet exposure assumed (lib/Net/UPnP/ControlPoint.pm:67-100).
- Advertised/compromised endpoint controls descriptions, service URLs, HTTP framing/body, SOAP/DIDL and media URLs (lib/Net/UPnP/ControlPoint.pm:100-113; lib/Net/UPnP/HTTP.pm:105-145; lib/Net/UPnP/AV/MediaServer.pm:197-241).
- Converter input reaches command option strings only when operator separately runs the example; exact Shell semantics need validation (examples/dms2vodcast.pl:6,272-308).
- No control of trusted account/CLI arguments/executables/CI credentials or device administration is assumed. Generic API invocation already within caller authority is not privilege gain.

### Security Objectives

- Bound duration, memory, counts and traversal for untrusted peers; discovery must terminate independently of peer activity.
- Prevent unauthenticated devices from exercising unintended outbound reachability; preserve caller-authorized SOAP structure (lib/Net/UPnP/ControlPoint.pm:85-100; lib/Net/UPnP/Service.pm:138-169,217-245).
- Converter must preserve execution/file/feed integrity while processing remote metadata, including CWD staging (examples/dms2vodcast.pl:189-224,285-308).
- Device-side gateway/renderer access policy is external; HTTP 200 and object construction do not authenticate peers.

### Assumptions

- No supplied deployment, tenants, credentials, production exposure or threat model. Generated model describes library and conditional examples.
- DEBUG defaults 0; globals/SetDebug permit caller changes. Socket/file/subprocess authority is inherited from caller (lib/Net/UPnP.pm:11-25).
- Local-network discovery documentation does not match a destination restriction: LOCATION accepts arbitrary matching HTTP hosts (lib/Net/UPnP/ControlPoint.pm:85-100,179-181).
- --base-directory documents RSS/MPEG4 placement; MPEG2 staging/deletion instead use CWD. Raw concatenation requires caller separator handling (examples/dms2vodcast.pl:31,43,103-104,189-191,289-308).
- Shell not vendored or found installed; Shell/curl/ffmpeg versions, PATH behavior and sandboxing unknown; build prerequisites only Test::More/version (examples/dms2vodcast.pl:6; Makefile.PL:11-14; Build.PL:11-14).
- No SECURITY.md resolved for root, lib, lib/Net, lib/Net/UPnP, AV, GW, examples, .github/workflows or t.
- Static offline review only; no runtime/exploit execution. Sole test checks module loading (t/UPnP.t:8-9).

## Findings

| Finding | Severity | Confidence | Detailed write-up |
| --- | --- | --- | --- |
| [Device HTTP responses can stall discovery indefinitely](#finding-1) | medium | high | inline below |
| [Repeated SSDP packets keep discovery running and growing](#finding-2) | medium | high | inline below |
| [SSDP responses can trigger blind requests to loopback services](#finding-3) | medium | high | inline below |
| [Device HTTP responses can exhaust caller memory](#finding-4) | medium | high | inline below |
| [Gateway success responses cause endless mapping enumeration](#finding-5) | medium | high | inline below |
| [Media metadata can alter generated RSS XML structure](#finding-6) | low | high | inline below |
| [Cyclic media containers cause unbounded recursive traversal](#finding-7) | low | high | inline below |

### Confidence Scale

| Label | Meaning |
| --- | --- |
| high | Direct evidence supports the finding with no material unresolved blocker. |
| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |
| low | Evidence is incomplete and the item is retained only for explicit follow-up. |

<a id="finding-1"></a>

### [1] Device HTTP responses can stall discovery indefinitely

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct current-source trace establishes input, absent local control and outcome; no live deployment or runtime reproduction was assumed. |
| Category | Missing network transaction deadline |
| CWE | CWE-400 |
| Affected lines | lib/Net/UPnP/HTTP.pm:105-108, lib/Net/UPnP/HTTP.pm:128-143, lib/Net/UPnP/ControlPoint.pm:99-100, lib/Net/UPnP/Service.pm:244-245, lib/Net/UPnP/Service.pm:318-319 |

#### Summary

A discovered device can accept a description request and withhold its status, header terminator or remaining body. `search()` then blocks indefinitely inside the shared HTTP transport; later SOAP actions/queries use the same transport.

#### Root Cause

`search()` synchronously forwards network-selected LOCATION to `post()`. Blocking connect/write/header/body reads have no absolute deadline; the UDP `select` timeout is suspended while `post()` runs.

**Discovery invokes synchronous GET** — `lib/Net/UPnP/ControlPoint.pm:80-100`

A responder-provided URL is passed immediately into HTTP::post.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Blocking socket operations** — `lib/Net/UPnP/HTTP.pm:86-100`

The target address is connected and request bytes written without deadline setup.

```perl
	$post_sockaddr = sockaddr_in($post_port, inet_aton($post_addr));
	socket(HTTP_SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
	unless( connect(HTTP_SOCK, $post_sockaddr) ) {
            print "connect($post_addr:$post_port) failed: $!" if ($Net::UPnP::DEBUG);
            return "";
        }
	select(HTTP_SOCK); $|=1; select(STDOUT);

	if ($Net::UPnP::DEBUG) {
		print $req_header;
		print $req_content;
	}
	
	print HTTP_SOCK $req_header;
	print HTTP_SOCK $req_content;
```

**Unbounded wait for response headers** — `lib/Net/UPnP/HTTP.pm:102-120`

A connected peer may withhold a line or blank terminator, preventing return.

```perl
	$res_status = "";
	$res_header = "";
	$res_header_cnt = 0;
	while(<HTTP_SOCK>) {
		if (m/^\r\n$/) {
			last;
		}
		$res_header_cnt++;
		if ($res_header_cnt == 1) {
			$res_status .= $_;
			next;
		}
		$res_header .= $_;
	}

	$res_content_len = 0;
	if($res_header =~ m/^Content-Length[: ]*(\d+)/i ) {
		$res_content_len = $1
	}
```

**Body readers share the missing deadline** — `lib/Net/UPnP/HTTP.pm:127-145`

All body framing branches may wait for peer data or EOF without an elapsed-time budget.

```perl
	$res_content = "";
	if ($res_chunked) {
		while(<HTTP_SOCK>) {
			s/[\r\n]//g;
			my $length = hex($_);
			my $chunk;

			read(HTTP_SOCK, $chunk, $length);
			$res_content .= $chunk;
		}
	}
	elsif ($res_content_len) {
		read(HTTP_SOCK, $res_content, $res_content_len);
	}
	else {
		while(<HTTP_SOCK>) {
			$res_content .= $_;
		}
	}
```

#### Validation

Parent verified the actual entrypoint, transformation, missing control and sink in current local source.

Validation method: Independent parent static source trace after worker discovery

**Discovery invokes synchronous GET** — `lib/Net/UPnP/ControlPoint.pm:80-100`

A responder-provided URL is passed immediately into HTTP::post.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Blocking socket operations** — `lib/Net/UPnP/HTTP.pm:86-100`

The target address is connected and request bytes written without deadline setup.

```perl
	$post_sockaddr = sockaddr_in($post_port, inet_aton($post_addr));
	socket(HTTP_SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
	unless( connect(HTTP_SOCK, $post_sockaddr) ) {
            print "connect($post_addr:$post_port) failed: $!" if ($Net::UPnP::DEBUG);
            return "";
        }
	select(HTTP_SOCK); $|=1; select(STDOUT);

	if ($Net::UPnP::DEBUG) {
		print $req_header;
		print $req_content;
	}
	
	print HTTP_SOCK $req_header;
	print HTTP_SOCK $req_content;
```

**Unbounded wait for response headers** — `lib/Net/UPnP/HTTP.pm:102-120`

A connected peer may withhold a line or blank terminator, preventing return.

```perl
	$res_status = "";
	$res_header = "";
	$res_header_cnt = 0;
	while(<HTTP_SOCK>) {
		if (m/^\r\n$/) {
			last;
		}
		$res_header_cnt++;
		if ($res_header_cnt == 1) {
			$res_status .= $_;
			next;
		}
		$res_header .= $_;
	}

	$res_content_len = 0;
	if($res_header =~ m/^Content-Length[: ]*(\d+)/i ) {
		$res_content_len = $1
	}
```

**Body readers share the missing deadline** — `lib/Net/UPnP/HTTP.pm:127-145`

All body framing branches may wait for peer data or EOF without an elapsed-time budget.

```perl
	$res_content = "";
	if ($res_chunked) {
		while(<HTTP_SOCK>) {
			s/[\r\n]//g;
			my $length = hex($_);
			my $chunk;

			read(HTTP_SOCK, $chunk, $length);
			$res_content .= $chunk;
		}
	}
	elsif ($res_content_len) {
		read(HTTP_SOCK, $res_content, $res_content_len);
	}
	else {
		while(<HTTP_SOCK>) {
			$res_content .= $_;
		}
	}
```

Assertions:
- `search()` synchronously forwards network-selected LOCATION to `post()`. Blocking connect/write/header/body reads have no absolute deadline; the UDP `select` timeout is suspended while `post()` runs.
- LAN responder or compromised selected device controls response progress; successful TCP connection is enough. It can stall the calling thread; no service deployment or whole-host outage is assumed.

Counterevidence and remaining uncertainty:
- UDP select mx timeout does not cover HTTP.
- Connection: close and connect failure handling do not bound established stream.

Limitations:
- Offline static analysis only; no application code, exploit input or network target executed.

#### Dataflow

ControlPoint.pm:99-100 synchronous GET -\> HTTP.pm:88,99-105,128-143 blocking connect/write/read with no deadline.

**Discovery invokes synchronous GET** — `lib/Net/UPnP/ControlPoint.pm:80-100`

A responder-provided URL is passed immediately into HTTP::post.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Blocking socket operations** — `lib/Net/UPnP/HTTP.pm:86-100`

The target address is connected and request bytes written without deadline setup.

```perl
	$post_sockaddr = sockaddr_in($post_port, inet_aton($post_addr));
	socket(HTTP_SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
	unless( connect(HTTP_SOCK, $post_sockaddr) ) {
            print "connect($post_addr:$post_port) failed: $!" if ($Net::UPnP::DEBUG);
            return "";
        }
	select(HTTP_SOCK); $|=1; select(STDOUT);

	if ($Net::UPnP::DEBUG) {
		print $req_header;
		print $req_content;
	}
	
	print HTTP_SOCK $req_header;
	print HTTP_SOCK $req_content;
```

**Unbounded wait for response headers** — `lib/Net/UPnP/HTTP.pm:102-120`

A connected peer may withhold a line or blank terminator, preventing return.

```perl
	$res_status = "";
	$res_header = "";
	$res_header_cnt = 0;
	while(<HTTP_SOCK>) {
		if (m/^\r\n$/) {
			last;
		}
		$res_header_cnt++;
		if ($res_header_cnt == 1) {
			$res_status .= $_;
			next;
		}
		$res_header .= $_;
	}

	$res_content_len = 0;
	if($res_header =~ m/^Content-Length[: ]*(\d+)/i ) {
		$res_content_len = $1
	}
```

**Body readers share the missing deadline** — `lib/Net/UPnP/HTTP.pm:127-145`

All body framing branches may wait for peer data or EOF without an elapsed-time budget.

```perl
	$res_content = "";
	if ($res_chunked) {
		while(<HTTP_SOCK>) {
			s/[\r\n]//g;
			my $length = hex($_);
			my $chunk;

			read(HTTP_SOCK, $chunk, $length);
			$res_content .= $chunk;
		}
	}
	elsif ($res_content_len) {
		read(HTTP_SOCK, $res_content, $res_content_len);
	}
	else {
		while(<HTTP_SOCK>) {
			$res_content .= $_;
		}
	}
```

#### Reachability

LAN responder or compromised selected device controls response progress; successful TCP connection is enough. It can stall the calling thread; no service deployment or whole-host outage is assumed.

Limitations:
- Deployment-specific impact was not verified.

#### Severity

**Medium** — Availability loss of the embedding caller is directly reachable from ordinary discovery. Local-network access limits the attacker, but one accepted response suffices.

A demonstrated sensitive production target or shared-service impact could raise severity; enforced caller isolation and budgets could lower it.

#### Remediation

Enforce an absolute monotonic deadline across connect, writes and all reads, limited by the remaining discovery budget; close the socket and return a defined timeout.

Tests:
- Silent accepted peer and slow-drip headers/body must stop at total deadline.
- Exercise description GET, SOAP action/query and all body framing branches.

Preventive controls:
- Centralize and document this boundary's explicit safety invariant.

<a id="finding-2"></a>

### [2] Repeated SSDP packets keep discovery running and growing

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct current-source trace establishes input, absent local control and outcome; no live deployment or runtime reproduction was assumed. |
| Category | Missing discovery duration and result budgets |
| CWE | CWE-400 |
| Affected lines | lib/Net/UPnP/ControlPoint.pm:80-86, lib/Net/UPnP/ControlPoint.pm:111-120 |

#### Summary

A peer can send datagrams more frequently than `mx*2` to keep `search()` alive indefinitely. Repeated valid replies also trigger repeated GETs and retained duplicate Device objects.

#### Root Cause

The full timeout is recomputed for each `select()` iteration rather than measured against a fixed end time. Packet count, fetch count and result count are unbounded, and responses are not deduplicated before fetching/appending.

**Idle timeout reset on every packet** — `lib/Net/UPnP/ControlPoint.pm:80-100`

Each loop starts a fresh mx\*2 wait; next on malformed LOCATION does not consume an overall budget.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Duplicate devices retained** — `lib/Net/UPnP/ControlPoint.pm:109-120`

Every successful repeated fetch creates and appends another Device without deduplication.

```perl
 		$post_content = $post_res->getcontent();

		$dev = Net::UPnP::Device->new();
 		$dev->setssdp($ssdp_res_msg);
		$dev->setdescription($post_content);
	
		if ($Net::UPnP::DEBUG) {
	 		print "ssdp = $ssdp_res_msg\n";
	 		print "description = $post_content\n";
	 	}

		push(@dev_list, $dev);
```

#### Validation

Parent verified the actual entrypoint, transformation, missing control and sink in current local source.

Validation method: Independent parent static source trace after worker discovery

**Idle timeout reset on every packet** — `lib/Net/UPnP/ControlPoint.pm:80-100`

Each loop starts a fresh mx\*2 wait; next on malformed LOCATION does not consume an overall budget.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Duplicate devices retained** — `lib/Net/UPnP/ControlPoint.pm:109-120`

Every successful repeated fetch creates and appends another Device without deduplication.

```perl
 		$post_content = $post_res->getcontent();

		$dev = Net::UPnP::Device->new();
 		$dev->setssdp($ssdp_res_msg);
		$dev->setdescription($post_content);
	
		if ($Net::UPnP::DEBUG) {
	 		print "ssdp = $ssdp_res_msg\n";
	 		print "description = $post_content\n";
	 	}

		push(@dev_list, $dev);
```

Assertions:
- The full timeout is recomputed for each `select()` iteration rather than measured against a fixed end time. Packet count, fetch count and result count are unbounded, and responses are not deduplicated before fetching/appending.
- A LAN sender needs the active discovery socket address. Even packets without LOCATION restart the wait; valid duplicate replies additionally grow memory.

Counterevidence and remaining uncertainty:
- 4096-byte cap and quiet-network timeout do not bound duration/results.

Limitations:
- Offline static analysis only; no application code, exploit input or network target executed.

#### Dataflow

ControlPoint.pm:80-86 resets mx\*2 wait every packet; :111-120 appends Device per successful duplicate fetch without dedup.

**Idle timeout reset on every packet** — `lib/Net/UPnP/ControlPoint.pm:80-100`

Each loop starts a fresh mx\*2 wait; next on malformed LOCATION does not consume an overall budget.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Duplicate devices retained** — `lib/Net/UPnP/ControlPoint.pm:109-120`

Every successful repeated fetch creates and appends another Device without deduplication.

```perl
 		$post_content = $post_res->getcontent();

		$dev = Net::UPnP::Device->new();
 		$dev->setssdp($ssdp_res_msg);
		$dev->setdescription($post_content);
	
		if ($Net::UPnP::DEBUG) {
	 		print "ssdp = $ssdp_res_msg\n";
	 		print "description = $post_content\n";
	 	}

		push(@dev_list, $dev);
```

#### Reachability

A LAN sender needs the active discovery socket address. Even packets without LOCATION restart the wait; valid duplicate replies additionally grow memory.

Limitations:
- Deployment-specific impact was not verified.

#### Severity

**Medium** — The public discovery operation can be held open by sustained peer activity; duplicate result retention is independent of individual HTTP byte/time limits.

A demonstrated sensitive production target or shared-service impact could raise severity; enforced caller isolation and budgets could lower it.

#### Remediation

Compute one absolute search deadline, pass remaining time into select and HTTP, and impose packet/fetch/result caps. Deduplicate USN/LOCATION using a bounded set before HTTP fetch.

Tests:
- Continuous malformed UDP and duplicate valid responses terminate within the total budget.
- Duplicate replies do not repeat GETs or add unbounded results.

Preventive controls:
- Centralize and document this boundary's explicit safety invariant.

<a id="finding-3"></a>

### [3] SSDP responses can trigger blind requests to loopback services

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct current-source trace establishes input, absent local control and outcome; no live deployment or runtime reproduction was assumed. |
| Category | Unrestricted discovery-derived request destination |
| CWE | CWE-918 |
| Affected lines | lib/Net/UPnP/ControlPoint.pm:90-100, lib/Net/UPnP/HTTP.pm:86-88, lib/Net/UPnP/Service.pm:138-152, lib/Net/UPnP/Service.pm:198-215, lib/Net/UPnP/Service.pm:285-302 |

#### Summary

A LAN responder can advertise `http://127.0.0.1:8080/...` as LOCATION and make the client issue a GET to a victim-local service. Later service URLs and URLBase can similarly redirect SOAP POSTs to unrelated origins.

#### Root Cause

`recv()` discards sender provenance; URL-pattern matching is the only destination gate. Parsed host/port/path reach `inet_aton()` and `connect()` without a resolved-address or peer-origin policy. Service endpoint construction likewise accepts absolute cross-origin URLs.

**Unauthenticated LOCATION controls destination** — `lib/Net/UPnP/ControlPoint.pm:80-100`

recv's sender is ignored while the response chooses the full HTTP target.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Advertised address becomes TCP destination** — `lib/Net/UPnP/HTTP.pm:86-100`

Host resolution and connect use the victim's network reachability with no destination check.

```perl
	$post_sockaddr = sockaddr_in($post_port, inet_aton($post_addr));
	socket(HTTP_SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
	unless( connect(HTTP_SOCK, $post_sockaddr) ) {
            print "connect($post_addr:$post_port) failed: $!" if ($Net::UPnP::DEBUG);
            return "";
        }
	select(HTTP_SOCK); $|=1; select(STDOUT);

	if ($Net::UPnP::DEBUG) {
		print $req_header;
		print $req_content;
	}
	
	print HTTP_SOCK $req_header;
	print HTTP_SOCK $req_content;
```

**Cross-origin service target accepted** — `lib/Net/UPnP/Service.pm:138-152`

Absolute controlURL bypasses base construction, and URLBase can replace the origin.

```perl
	$location_url = $dev->getlocation();
	$url_base = $dev->geturlbase();
	$ctrl_url = $this->getcontrolurl();

	#print "$location_url\n";
	#print "$url_base\n";
	#print "$ctrl_url\n";
		
	unless ($ctrl_url =~ m{http://(.*)}i) {
		if (0 < length($url_base)) {
			# Thanks for Thus0 (2005/01/12)
			if (rindex($url_base, '/') == (length($url_base)-1) && index($ctrl_url, '/') == 0) {
				$ctrl_url = $url_base . substr($ctrl_url, 1);
			} else {
				$ctrl_url = $url_base . $ctrl_url;
```

**Resolved target used for action** — `lib/Net/UPnP/Service.pm:198-218`

postaction parses host/port/path from the device-provided target.

```perl
	$dev = $this->getdevice();
	$ctrl_url = $this->getcontrolurl();
	$ctrl_url = $this->getposturl($ctrl_url);
	
	unless ($ctrl_url =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
		#print "Invalid URL : $ctrl_url\n";
		$post_res = Net::UPnP::HTTPResponse->new();
		$action_res->sethttpresponse($post_res);
		return $action_res;
	}
	$post_addr = $1;
	$post_port = $2 || 80;
	if (index($3, '/') == 0) {
		$post_path = $3;
	}
	else {
		$post_path = '/' . $3;
	}

	$service_type = $this->getservicetype();
	$soap_action = '"' . $service_type . '#' . $action_name . '"';
```

**Action targets resolved address** — `lib/Net/UPnP/Service.pm:244-247`

postsoap receives that destination and caller operation body.

```perl
	$http_req = Net::UPnP::HTTP->new();
	$post_res = $http_req->postsoap($post_addr, $post_port, $post_path, $soap_action, $soap_content);

	$action_res->sethttpresponse($post_res);
```

#### Validation

Parent verified the actual entrypoint, transformation, missing control and sink in current local source.

Validation method: Independent parent static source trace after worker discovery

**Unauthenticated LOCATION controls destination** — `lib/Net/UPnP/ControlPoint.pm:80-100`

recv's sender is ignored while the response chooses the full HTTP target.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Advertised address becomes TCP destination** — `lib/Net/UPnP/HTTP.pm:86-100`

Host resolution and connect use the victim's network reachability with no destination check.

```perl
	$post_sockaddr = sockaddr_in($post_port, inet_aton($post_addr));
	socket(HTTP_SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
	unless( connect(HTTP_SOCK, $post_sockaddr) ) {
            print "connect($post_addr:$post_port) failed: $!" if ($Net::UPnP::DEBUG);
            return "";
        }
	select(HTTP_SOCK); $|=1; select(STDOUT);

	if ($Net::UPnP::DEBUG) {
		print $req_header;
		print $req_content;
	}
	
	print HTTP_SOCK $req_header;
	print HTTP_SOCK $req_content;
```

**Cross-origin service target accepted** — `lib/Net/UPnP/Service.pm:138-152`

Absolute controlURL bypasses base construction, and URLBase can replace the origin.

```perl
	$location_url = $dev->getlocation();
	$url_base = $dev->geturlbase();
	$ctrl_url = $this->getcontrolurl();

	#print "$location_url\n";
	#print "$url_base\n";
	#print "$ctrl_url\n";
		
	unless ($ctrl_url =~ m{http://(.*)}i) {
		if (0 < length($url_base)) {
			# Thanks for Thus0 (2005/01/12)
			if (rindex($url_base, '/') == (length($url_base)-1) && index($ctrl_url, '/') == 0) {
				$ctrl_url = $url_base . substr($ctrl_url, 1);
			} else {
				$ctrl_url = $url_base . $ctrl_url;
```

**Resolved target used for action** — `lib/Net/UPnP/Service.pm:198-218`

postaction parses host/port/path from the device-provided target.

```perl
	$dev = $this->getdevice();
	$ctrl_url = $this->getcontrolurl();
	$ctrl_url = $this->getposturl($ctrl_url);
	
	unless ($ctrl_url =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
		#print "Invalid URL : $ctrl_url\n";
		$post_res = Net::UPnP::HTTPResponse->new();
		$action_res->sethttpresponse($post_res);
		return $action_res;
	}
	$post_addr = $1;
	$post_port = $2 || 80;
	if (index($3, '/') == 0) {
		$post_path = $3;
	}
	else {
		$post_path = '/' . $3;
	}

	$service_type = $this->getservicetype();
	$soap_action = '"' . $service_type . '#' . $action_name . '"';
```

**Action targets resolved address** — `lib/Net/UPnP/Service.pm:244-247`

postsoap receives that destination and caller operation body.

```perl
	$http_req = Net::UPnP::HTTP->new();
	$post_res = $http_req->postsoap($post_addr, $post_port, $post_path, $soap_action, $soap_content);

	$action_res->sethttpresponse($post_res);
```

Assertions:
- `recv()` discards sender provenance; URL-pattern matching is the only destination gate. Parsed host/port/path reach `inet_aton()` and `connect()` without a resolved-address or peer-origin policy. Service endpoint construction likewise accepts absolute cross-origin URLs.
- Attacker must deliver a discovery reply during search. Meaningful impact requires a reachable target service accepting unauthenticated HTTP or a GET with side effects; subsequent POSTs require caller use of the advertised service.

Counterevidence and remaining uncertainty:
- Following advertised URL intended; only HTTP accepted, no cookies/auth attached.
- Loopback IPv4/DNS/arbitrary ports allowed.

Limitations:
- Offline static analysis only; no application code, exploit input or network target executed.

#### Dataflow

ControlPoint.pm:80-100 ignores sender, passes LOCATION host/port/path to HTTP.pm:86-88 inet_aton/connect; Service.pm:138-169 absolute controlURL/URLBase selects later POST target.

**Unauthenticated LOCATION controls destination** — `lib/Net/UPnP/ControlPoint.pm:80-100`

recv's sender is ignored while the response chooses the full HTTP target.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Advertised address becomes TCP destination** — `lib/Net/UPnP/HTTP.pm:86-100`

Host resolution and connect use the victim's network reachability with no destination check.

```perl
	$post_sockaddr = sockaddr_in($post_port, inet_aton($post_addr));
	socket(HTTP_SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
	unless( connect(HTTP_SOCK, $post_sockaddr) ) {
            print "connect($post_addr:$post_port) failed: $!" if ($Net::UPnP::DEBUG);
            return "";
        }
	select(HTTP_SOCK); $|=1; select(STDOUT);

	if ($Net::UPnP::DEBUG) {
		print $req_header;
		print $req_content;
	}
	
	print HTTP_SOCK $req_header;
	print HTTP_SOCK $req_content;
```

**Cross-origin service target accepted** — `lib/Net/UPnP/Service.pm:138-152`

Absolute controlURL bypasses base construction, and URLBase can replace the origin.

```perl
	$location_url = $dev->getlocation();
	$url_base = $dev->geturlbase();
	$ctrl_url = $this->getcontrolurl();

	#print "$location_url\n";
	#print "$url_base\n";
	#print "$ctrl_url\n";
		
	unless ($ctrl_url =~ m{http://(.*)}i) {
		if (0 < length($url_base)) {
			# Thanks for Thus0 (2005/01/12)
			if (rindex($url_base, '/') == (length($url_base)-1) && index($ctrl_url, '/') == 0) {
				$ctrl_url = $url_base . substr($ctrl_url, 1);
			} else {
				$ctrl_url = $url_base . $ctrl_url;
```

**Resolved target used for action** — `lib/Net/UPnP/Service.pm:198-218`

postaction parses host/port/path from the device-provided target.

```perl
	$dev = $this->getdevice();
	$ctrl_url = $this->getcontrolurl();
	$ctrl_url = $this->getposturl($ctrl_url);
	
	unless ($ctrl_url =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
		#print "Invalid URL : $ctrl_url\n";
		$post_res = Net::UPnP::HTTPResponse->new();
		$action_res->sethttpresponse($post_res);
		return $action_res;
	}
	$post_addr = $1;
	$post_port = $2 || 80;
	if (index($3, '/') == 0) {
		$post_path = $3;
	}
	else {
		$post_path = '/' . $3;
	}

	$service_type = $this->getservicetype();
	$soap_action = '"' . $service_type . '#' . $action_name . '"';
```

**Action targets resolved address** — `lib/Net/UPnP/Service.pm:244-247`

postsoap receives that destination and caller operation body.

```perl
	$http_req = Net::UPnP::HTTP->new();
	$post_res = $http_req->postsoap($post_addr, $post_port, $post_path, $soap_action, $soap_content);

	$action_res->sethttpresponse($post_res);
```

#### Reachability

Attacker must deliver a discovery reply during search. Meaningful impact requires a reachable target service accepting unauthenticated HTTP or a GET with side effects; subsequent POSTs require caller use of the advertised service.

Limitations:
- Blind requests only; no response exfiltration or concrete privileged target demonstrated.

#### Severity

**Medium** — The automatic GET crosses LAN-to-victim-loopback reachability. No response exfiltration, credentials, cookies or specific privileged target are established; impact depends on target behavior.

A demonstrated sensitive production target or shared-service impact could raise severity; enforced caller isolation and budgets could lower it.

#### Remediation

Retain SSDP sender provenance and enforce a caller-configurable resolved-address policy before connect, rejecting loopback/unrelated destinations by default. Bind subsequent service URLs to the permitted device origin; explicitly allow supported proxy/multihomed cases.

Tests:
- Reject loopback and disallowed resolved destinations for LOCATION, URLBase and absolute controlURL.
- Ensure allowed device/proxy origins still work without DNS resolution/check-use gaps.

Preventive controls:
- Centralize and document this boundary's explicit safety invariant.

<a id="finding-4"></a>

### [4] Device HTTP responses can exhaust caller memory

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct current-source trace establishes input, absent local control and outcome; no live deployment or runtime reproduction was assumed. |
| Category | Unbounded response buffering |
| CWE | CWE-789 |
| Affected lines | lib/Net/UPnP/HTTP.pm:114-119, lib/Net/UPnP/HTTP.pm:131-143, lib/Net/UPnP/ControlPoint.pm:99-100, lib/Net/UPnP/Service.pm:244-245, lib/Net/UPnP/Service.pm:318-319 |

#### Summary

A discovered device can send arbitrarily large header lines, headers or bodies. The client buffers them in Perl strings without a byte budget, allowing memory exhaustion during discovery or SOAP operations.

#### Root Cause

`post()` reads complete lines, appends headers and EOF/chunked bodies, and passes peer-selected Content-Length/chunk sizes directly to `read()`. There is no maximum line/header/chunk/body budget before buffering.

**Network responder reaches HTTP reader** — `lib/Net/UPnP/ControlPoint.pm:80-100`

Ordinary discovery causes an attacker-controlled response to be processed.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Unbounded header buffering** — `lib/Net/UPnP/HTTP.pm:102-120`

Line reads and aggregate append accept arbitrary amounts of peer-supplied header data.

```perl
	$res_status = "";
	$res_header = "";
	$res_header_cnt = 0;
	while(<HTTP_SOCK>) {
		if (m/^\r\n$/) {
			last;
		}
		$res_header_cnt++;
		if ($res_header_cnt == 1) {
			$res_status .= $_;
			next;
		}
		$res_header .= $_;
	}

	$res_content_len = 0;
	if($res_header =~ m/^Content-Length[: ]*(\d+)/i ) {
		$res_content_len = $1
	}
```

**Peer-selected lengths and body accumulation** — `lib/Net/UPnP/HTTP.pm:127-145`

Large Content-Length/chunk values and unlimited EOF-delimited append have no aggregate body cap.

```perl
	$res_content = "";
	if ($res_chunked) {
		while(<HTTP_SOCK>) {
			s/[\r\n]//g;
			my $length = hex($_);
			my $chunk;

			read(HTTP_SOCK, $chunk, $length);
			$res_content .= $chunk;
		}
	}
	elsif ($res_content_len) {
		read(HTTP_SOCK, $res_content, $res_content_len);
	}
	else {
		while(<HTTP_SOCK>) {
			$res_content .= $_;
		}
	}
```

#### Validation

Parent verified the actual entrypoint, transformation, missing control and sink in current local source.

Validation method: Independent parent static source trace after worker discovery

**Network responder reaches HTTP reader** — `lib/Net/UPnP/ControlPoint.pm:80-100`

Ordinary discovery causes an attacker-controlled response to be processed.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Unbounded header buffering** — `lib/Net/UPnP/HTTP.pm:102-120`

Line reads and aggregate append accept arbitrary amounts of peer-supplied header data.

```perl
	$res_status = "";
	$res_header = "";
	$res_header_cnt = 0;
	while(<HTTP_SOCK>) {
		if (m/^\r\n$/) {
			last;
		}
		$res_header_cnt++;
		if ($res_header_cnt == 1) {
			$res_status .= $_;
			next;
		}
		$res_header .= $_;
	}

	$res_content_len = 0;
	if($res_header =~ m/^Content-Length[: ]*(\d+)/i ) {
		$res_content_len = $1
	}
```

**Peer-selected lengths and body accumulation** — `lib/Net/UPnP/HTTP.pm:127-145`

Large Content-Length/chunk values and unlimited EOF-delimited append have no aggregate body cap.

```perl
	$res_content = "";
	if ($res_chunked) {
		while(<HTTP_SOCK>) {
			s/[\r\n]//g;
			my $length = hex($_);
			my $chunk;

			read(HTTP_SOCK, $chunk, $length);
			$res_content .= $chunk;
		}
	}
	elsif ($res_content_len) {
		read(HTTP_SOCK, $res_content, $res_content_len);
	}
	else {
		while(<HTTP_SOCK>) {
			$res_content .= $_;
		}
	}
```

Assertions:
- `post()` reads complete lines, appends headers and EOF/chunked bodies, and passes peer-selected Content-Length/chunk sizes directly to `read()`. There is no maximum line/header/chunk/body budget before buffering.
- A LAN-advertised or selected malicious device can stream valid data quickly; it need not stall a socket, use compression or expand XML entities.

Counterevidence and remaining uncertainty:
- 4096-byte SSDP cap unrelated.
- Content-Length regex first-header-only; EOF fallback unbounded.

Limitations:
- Offline static analysis only; no application code, exploit input or network target executed.

#### Dataflow

HTTP.pm:105-119 unbounded header append; :128-143 arbitrary chunk/Content-Length read and EOF accumulation.

**Network responder reaches HTTP reader** — `lib/Net/UPnP/ControlPoint.pm:80-100`

Ordinary discovery causes an attacker-controlled response to be processed.

```perl
	while( select($rout = $rin, undef, undef, ($args{mx} * 2)) ) {
		recv(SSDP_SOCK, $ssdp_res_msg, 4096, 0);
		
		print "$ssdp_res_msg" if ($Net::UPnP::DEBUG);
		
		unless ($ssdp_res_msg =~ m/LOCATION[ :]+(.*)\r/i) {
			next;
		}		
		$dev_location = $1;
		print "dev_location=$dev_location\n" if ($Net::UPnP::DEBUG);
                unless ($dev_location =~ m{http://([0-9a-z.-]+)(?::(\d+))?/(.*)}i) {
                        print "bad dev_location: $dev_location\n" if ($Net::UPnP::DEBUG);
			next;
		}
		$dev_addr = $1;
		$dev_port = $2 || 80;
		$dev_path = '/' . $3;
		print "dev_addr=$dev_addr dev_port=$dev_port dev_path=$dev_path\n" if ($Net::UPnP::DEBUG);
		
		$http_req = Net::UPnP::HTTP->new();
		$post_res = $http_req->post($dev_addr, $dev_port, "GET", $dev_path, "", "");
```

**Unbounded header buffering** — `lib/Net/UPnP/HTTP.pm:102-120`

Line reads and aggregate append accept arbitrary amounts of peer-supplied header data.

```perl
	$res_status = "";
	$res_header = "";
	$res_header_cnt = 0;
	while(<HTTP_SOCK>) {
		if (m/^\r\n$/) {
			last;
		}
		$res_header_cnt++;
		if ($res_header_cnt == 1) {
			$res_status .= $_;
			next;
		}
		$res_header .= $_;
	}

	$res_content_len = 0;
	if($res_header =~ m/^Content-Length[: ]*(\d+)/i ) {
		$res_content_len = $1
	}
```

**Peer-selected lengths and body accumulation** — `lib/Net/UPnP/HTTP.pm:127-145`

Large Content-Length/chunk values and unlimited EOF-delimited append have no aggregate body cap.

```perl
	$res_content = "";
	if ($res_chunked) {
		while(<HTTP_SOCK>) {
			s/[\r\n]//g;
			my $length = hex($_);
			my $chunk;

			read(HTTP_SOCK, $chunk, $length);
			$res_content .= $chunk;
		}
	}
	elsif ($res_content_len) {
		read(HTTP_SOCK, $res_content, $res_content_len);
	}
	else {
		while(<HTTP_SOCK>) {
			$res_content .= $_;
		}
	}
```

#### Reachability

A LAN-advertised or selected malicious device can stream valid data quickly; it need not stall a socket, use compression or expand XML entities.

Limitations:
- Deployment-specific impact was not verified.

#### Severity

**Medium** — Unbounded remotely controlled allocation threatens process memory. A malicious device is required; no system-wide OOM outcome is asserted.

A demonstrated sensitive production target or shared-service impact could raise severity; enforced caller isolation and budgets could lower it.

#### Remediation

Limit line length, total header bytes, chunk size and cumulative body bytes before buffering; use fixed-size reads and reject over-budget declared lengths.

Tests:
- Oversized header line and aggregate headers are rejected.
- Content-Length, chunked and EOF responses exceeding the same body budget fail without large buffers.

Preventive controls:
- Centralize and document this boundary's explicit safety invariant.

<a id="finding-5"></a>

### [5] Gateway success responses cause endless mapping enumeration

| Field | Value |
| --- | --- |
| Severity | medium |
| Confidence | high |
| Confidence rationale | Direct current-source trace establishes input, absent local control and outcome; no live deployment or runtime reproduction was assumed. |
| Category | Peer-controlled enumeration termination |
| CWE | CWE-835 |
| Affected lines | lib/Net/UPnP/GW/Gateway.pm:138-151, lib/Net/UPnP/GW/Gateway.pm:106-109 |

#### Summary

A malicious WANIPConnection service can return HTTP 200 for every requested mapping index. `getportmappingentries()` never returns and retains every parsed response, even when each response is small and fast.

#### Root Cause

The unconditional loop stops only on peer-supplied non-200 status, increments the index and pushes every response without an entry or elapsed-time cap.

**Peer status is sole loop termination** — `lib/Net/UPnP/GW/Gateway.pm:138-152`

Each successful response is appended and advances to another request with no local count/deadline control.

```perl
        $n = 0;
        while( 1 ) {
		%req_arg = (
				'NewPortMappingIndex' => $n,
			);
	
		$action_res = $wanipcon_service->postaction("GetGenericPortMappingEntry", \%req_arg);
		#print "[$n]" .$action_res->getstatuscode()  . "\n";
		#print %req_arg;
                last if ($action_res->getstatuscode() != 200);
		$arg_list = $action_res->getargumentlist();
		#print $arg_list;
		push(@port_mapping, $arg_list);
                ++$n;
	}
```

**Enumeration uses SOAP transport** — `lib/Net/UPnP/Service.pm:244-247`

Gateway postaction requests go through the shared HTTP client; limiting one exchange does not bound their number.

```perl
	$http_req = Net::UPnP::HTTP->new();
	$post_res = $http_req->postsoap($post_addr, $post_port, $post_path, $soap_action, $soap_content);

	$action_res->sethttpresponse($post_res);
```

#### Validation

Parent verified the actual entrypoint, transformation, missing control and sink in current local source.

Validation method: Independent parent static source trace after worker discovery

**Peer status is sole loop termination** — `lib/Net/UPnP/GW/Gateway.pm:138-152`

Each successful response is appended and advances to another request with no local count/deadline control.

```perl
        $n = 0;
        while( 1 ) {
		%req_arg = (
				'NewPortMappingIndex' => $n,
			);
	
		$action_res = $wanipcon_service->postaction("GetGenericPortMappingEntry", \%req_arg);
		#print "[$n]" .$action_res->getstatuscode()  . "\n";
		#print %req_arg;
                last if ($action_res->getstatuscode() != 200);
		$arg_list = $action_res->getargumentlist();
		#print $arg_list;
		push(@port_mapping, $arg_list);
                ++$n;
	}
```

**Enumeration uses SOAP transport** — `lib/Net/UPnP/Service.pm:244-247`

Gateway postaction requests go through the shared HTTP client; limiting one exchange does not bound their number.

```perl
	$http_req = Net::UPnP::HTTP->new();
	$post_res = $http_req->postsoap($post_addr, $post_port, $post_path, $soap_action, $soap_content);

	$action_res->sethttpresponse($post_res);
```

Assertions:
- The unconditional loop stops only on peer-supplied non-200 status, increments the index and pushes every response without an entry or elapsed-time cap.
- Victim enumerates an advertised/impersonated gateway, including via number-of-entries fallback or gateway dump/list examples. The attacker need not control the real router or its mappings.

Counterevidence and remaining uncertainty:
- Conforming gateway eventually fails; no entry/count/time validation.

Limitations:
- Offline static analysis only; no application code, exploit input or network target executed.

#### Dataflow

Gateway.pm:138-151 while(1) postaction GetGenericPortMappingEntry, only status !=200 breaks, pushes every arg list.

**Peer status is sole loop termination** — `lib/Net/UPnP/GW/Gateway.pm:138-152`

Each successful response is appended and advances to another request with no local count/deadline control.

```perl
        $n = 0;
        while( 1 ) {
		%req_arg = (
				'NewPortMappingIndex' => $n,
			);
	
		$action_res = $wanipcon_service->postaction("GetGenericPortMappingEntry", \%req_arg);
		#print "[$n]" .$action_res->getstatuscode()  . "\n";
		#print %req_arg;
                last if ($action_res->getstatuscode() != 200);
		$arg_list = $action_res->getargumentlist();
		#print $arg_list;
		push(@port_mapping, $arg_list);
                ++$n;
	}
```

**Enumeration uses SOAP transport** — `lib/Net/UPnP/Service.pm:244-247`

Gateway postaction requests go through the shared HTTP client; limiting one exchange does not bound their number.

```perl
	$http_req = Net::UPnP::HTTP->new();
	$post_res = $http_req->postsoap($post_addr, $post_port, $post_path, $soap_action, $soap_content);

	$action_res->sethttpresponse($post_res);
```

#### Reachability

Victim enumerates an advertised/impersonated gateway, including via number-of-entries fallback or gateway dump/list examples. The attacker need not control the real router or its mappings.

Limitations:
- Deployment-specific impact was not verified.

#### Severity

**Medium** — Caller memory and availability are exposed through an ordinary library enumeration API; honest per-request timeout/size bounds do not close this loop.

A demonstrated sensitive production target or shared-service impact could raise severity; enforced caller isolation and budgets could lower it.

#### Remediation

Enforce a maximum mapping count/protocol index and overall deadline, validate entries and return an explicit truncated/error outcome if the peer fails to terminate.

Tests:
- A gateway returning endless valid 200 responses stops at the count/time limit.
- Normal terminal errors and number-of-entries fallback retain defined behavior.

Preventive controls:
- Centralize and document this boundary's explicit safety invariant.

<a id="finding-6"></a>

### [6] Media metadata can alter generated RSS XML structure

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Direct current-source trace establishes input, absent local control and outcome; no live deployment or runtime reproduction was assumed. |
| Category | Missing XML text and attribute escaping |
| CWE | CWE-91 |
| Affected lines | examples/dms2vodcast.pl:210-217, lib/Net/UPnP/AV/MediaServer.pm:223-227, examples/dms2vodcast.pl:321-325 |

#### Summary

When a malicious media item is included in output, device title and generated filename are interpolated directly into RSS. Crafted title markup or attribute quotes can corrupt the feed or add unintended XML fields.

#### Root Cause

SOAP entity-decoded DIDL is regex-extracted rather than validated; its title enters the item info hash unchanged, then a heredoc emits it as XML. Filename substitutions remove slashes/spaces but leave XML-significant quotes and angle brackets.

**SOAP Result entity decoding** — `lib/Net/UPnP/ActionResponse.pm:105-123`

Escaped result content is decoded to text consumed by the DIDL parser.

```perl
	$res_content = $http_res->getcontent();
	if ($res_content =~ m/<.*Response[^>]*>\s*(.*)\s*<\/.*Response>/si) {
		$soap_response = $1;
	}
	
	while ($soap_response =~ m/<([^>]*)>([^<]*)<\/[^>]*>/sg) {
		$arg_name = $1;
		if (0 < index($arg_name, ' ')) {
			@arg_name_token = split(/ /, $arg_name);
			if (0 < @arg_name_token) {
				$arg_name = $arg_name_token[0];
			}
		}
		$arg_value = $2;
		$arg_value = Net::UPnP::HTTP::xmldecode($arg_value);
		$argument_list{$arg_name} = $arg_value;
	}
	
	return \%argument_list;
```

**Title extracted without validation** — `lib/Net/UPnP/AV/MediaServer.pm:220-241`

Regex extraction accepts markup-like title text and sets item fields.

```perl
	while ($result =~ m/<item(.*?)<\/item>/sgi) {
		$content = $1;
		$item= Net::UPnP::AV::Item->new();
		if ($content =~ m/id=\"(.*?)\"/si) {
			$item->setid($1);
		}
		if ($content =~ m/<dc:title>(.*)<\/dc:title>/si) {
			$item->settitle($1);
		}
		if ($content =~ m/<dc:date>(.*)<\/dc:date>/si) {
			$item->setdate($1);
		}
		if ($content =~ m/<res[^>]*>(.*?)<\/res>/si) {
			$item->seturl(Net::UPnP::HTTP::xmldecode($1));
		}
		if ($content =~ m/protocolInfo=\"http-get:[^:]*:([^:]*):.*\"/si) {
			$item->setcontenttype($1);
		}
		elsif ($content =~ m/protocolInfo=\"[^:]*:[^:]:([^:]*):.*\"/si) {
			$item->setcontenttype($1);
		}
		push (@content_list, $item);
```

**Remote names retained in filenames** — `examples/dms2vodcast.pl:280-291`

Filename cleanup does not escape XML-significant characters for later RSS output.

```perl
	my $dev = $mediaServer->getdevice();
	my $dev_friendlyname = $dev->getfriendlyname();
	my $dev_udn = $dev->getudn();
	$dev_udn =~ s/:/-/g;
	
	my $filename_body = $dev_friendlyname . "_" . $dev_udn . "_" . $objid;
	$filename_body =~ s/ //g;
	$filename_body =~ s/\//-/g;
	
	my $mpeg2_file_name = $filename_body . ".mpeg";
	my $mpeg4_file_name = $filename_body . "_" . $mp4_format . ".m4v";
	my $output_mpeg4_file_name = $base_directory . $mpeg4_file_name;
```

**Item title and filename preserved** — `examples/dms2vodcast.pl:321-327`

Converted item info stores the same remote title and derived filename.

```perl
	my %info = (
		'objid' => $objid,
		'title' => $title,
		'file_name' => $mpeg4_file_name,
		'file_size' => $mpeg4_file_size,
	);
	
```

**Raw XML heredoc interpolation** — `examples/dms2vodcast.pl:205-220`

Title becomes element content and the link becomes an attribute without XML escaping.

```perl
	$title = $content->{'title'};	
	$fname = $content->{'file_name'};
	$fsize = $content->{'file_size'};

$mp4_link = $rss_base_url . $fname;
$mp4_item = <<"RSS_MP4_ITEM";
<item>
<title>$title</title>
<guid isPermalink="false">$mp4_link</guid>
<enclosure url="$mp4_link" length="$fsize" type="video/mp4" />
</item>
RSS_MP4_ITEM
	print RSS_FILE $mp4_item;
}

$rss_footer = <<"RSS_FOOTER";
```

#### Validation

Parent verified the actual entrypoint, transformation, missing control and sink in current local source.

Validation method: Independent parent static source trace after worker discovery

**SOAP Result entity decoding** — `lib/Net/UPnP/ActionResponse.pm:105-123`

Escaped result content is decoded to text consumed by the DIDL parser.

```perl
	$res_content = $http_res->getcontent();
	if ($res_content =~ m/<.*Response[^>]*>\s*(.*)\s*<\/.*Response>/si) {
		$soap_response = $1;
	}
	
	while ($soap_response =~ m/<([^>]*)>([^<]*)<\/[^>]*>/sg) {
		$arg_name = $1;
		if (0 < index($arg_name, ' ')) {
			@arg_name_token = split(/ /, $arg_name);
			if (0 < @arg_name_token) {
				$arg_name = $arg_name_token[0];
			}
		}
		$arg_value = $2;
		$arg_value = Net::UPnP::HTTP::xmldecode($arg_value);
		$argument_list{$arg_name} = $arg_value;
	}
	
	return \%argument_list;
```

**Title extracted without validation** — `lib/Net/UPnP/AV/MediaServer.pm:220-241`

Regex extraction accepts markup-like title text and sets item fields.

```perl
	while ($result =~ m/<item(.*?)<\/item>/sgi) {
		$content = $1;
		$item= Net::UPnP::AV::Item->new();
		if ($content =~ m/id=\"(.*?)\"/si) {
			$item->setid($1);
		}
		if ($content =~ m/<dc:title>(.*)<\/dc:title>/si) {
			$item->settitle($1);
		}
		if ($content =~ m/<dc:date>(.*)<\/dc:date>/si) {
			$item->setdate($1);
		}
		if ($content =~ m/<res[^>]*>(.*?)<\/res>/si) {
			$item->seturl(Net::UPnP::HTTP::xmldecode($1));
		}
		if ($content =~ m/protocolInfo=\"http-get:[^:]*:([^:]*):.*\"/si) {
			$item->setcontenttype($1);
		}
		elsif ($content =~ m/protocolInfo=\"[^:]*:[^:]:([^:]*):.*\"/si) {
			$item->setcontenttype($1);
		}
		push (@content_list, $item);
```

**Remote names retained in filenames** — `examples/dms2vodcast.pl:280-291`

Filename cleanup does not escape XML-significant characters for later RSS output.

```perl
	my $dev = $mediaServer->getdevice();
	my $dev_friendlyname = $dev->getfriendlyname();
	my $dev_udn = $dev->getudn();
	$dev_udn =~ s/:/-/g;
	
	my $filename_body = $dev_friendlyname . "_" . $dev_udn . "_" . $objid;
	$filename_body =~ s/ //g;
	$filename_body =~ s/\//-/g;
	
	my $mpeg2_file_name = $filename_body . ".mpeg";
	my $mpeg4_file_name = $filename_body . "_" . $mp4_format . ".m4v";
	my $output_mpeg4_file_name = $base_directory . $mpeg4_file_name;
```

**Item title and filename preserved** — `examples/dms2vodcast.pl:321-327`

Converted item info stores the same remote title and derived filename.

```perl
	my %info = (
		'objid' => $objid,
		'title' => $title,
		'file_name' => $mpeg4_file_name,
		'file_size' => $mpeg4_file_size,
	);
	
```

**Raw XML heredoc interpolation** — `examples/dms2vodcast.pl:205-220`

Title becomes element content and the link becomes an attribute without XML escaping.

```perl
	$title = $content->{'title'};	
	$fname = $content->{'file_name'};
	$fsize = $content->{'file_size'};

$mp4_link = $rss_base_url . $fname;
$mp4_item = <<"RSS_MP4_ITEM";
<item>
<title>$title</title>
<guid isPermalink="false">$mp4_link</guid>
<enclosure url="$mp4_link" length="$fsize" type="video/mp4" />
</item>
RSS_MP4_ITEM
	print RSS_FILE $mp4_item;
}

$rss_footer = <<"RSS_FOOTER";
```

Assertions:
- SOAP entity-decoded DIDL is regex-extracted rather than validated; its title enters the item info hash unchanged, then a heredoc emits it as XML. Filename substitutions remove slashes/spaces but leave XML-significant quotes and angle brackets.
- Operator runs dms2vodcast and item conversion succeeds or a corresponding nonempty output file already exists; feed publication/consumption is external. A title containing closing RSS title markup can survive the regex extraction.

Counterevidence and remaining uncertainty:
- Requires successful item inclusion; malformed DIDL accepted by regex.
- Unix slash replacement defeats ordinary ../ traversal.

Limitations:
- Offline static analysis only; no application code, exploit input or network target executed.

#### Dataflow

ActionResponse.pm:118-120 decode -\> MediaServer.pm:223-227 title -\> dms2vodcast.pl:321-325 info -\> :210-217 raw title/enclosure filename interpolation.

**SOAP Result entity decoding** — `lib/Net/UPnP/ActionResponse.pm:105-123`

Escaped result content is decoded to text consumed by the DIDL parser.

```perl
	$res_content = $http_res->getcontent();
	if ($res_content =~ m/<.*Response[^>]*>\s*(.*)\s*<\/.*Response>/si) {
		$soap_response = $1;
	}
	
	while ($soap_response =~ m/<([^>]*)>([^<]*)<\/[^>]*>/sg) {
		$arg_name = $1;
		if (0 < index($arg_name, ' ')) {
			@arg_name_token = split(/ /, $arg_name);
			if (0 < @arg_name_token) {
				$arg_name = $arg_name_token[0];
			}
		}
		$arg_value = $2;
		$arg_value = Net::UPnP::HTTP::xmldecode($arg_value);
		$argument_list{$arg_name} = $arg_value;
	}
	
	return \%argument_list;
```

**Title extracted without validation** — `lib/Net/UPnP/AV/MediaServer.pm:220-241`

Regex extraction accepts markup-like title text and sets item fields.

```perl
	while ($result =~ m/<item(.*?)<\/item>/sgi) {
		$content = $1;
		$item= Net::UPnP::AV::Item->new();
		if ($content =~ m/id=\"(.*?)\"/si) {
			$item->setid($1);
		}
		if ($content =~ m/<dc:title>(.*)<\/dc:title>/si) {
			$item->settitle($1);
		}
		if ($content =~ m/<dc:date>(.*)<\/dc:date>/si) {
			$item->setdate($1);
		}
		if ($content =~ m/<res[^>]*>(.*?)<\/res>/si) {
			$item->seturl(Net::UPnP::HTTP::xmldecode($1));
		}
		if ($content =~ m/protocolInfo=\"http-get:[^:]*:([^:]*):.*\"/si) {
			$item->setcontenttype($1);
		}
		elsif ($content =~ m/protocolInfo=\"[^:]*:[^:]:([^:]*):.*\"/si) {
			$item->setcontenttype($1);
		}
		push (@content_list, $item);
```

**Remote names retained in filenames** — `examples/dms2vodcast.pl:280-291`

Filename cleanup does not escape XML-significant characters for later RSS output.

```perl
	my $dev = $mediaServer->getdevice();
	my $dev_friendlyname = $dev->getfriendlyname();
	my $dev_udn = $dev->getudn();
	$dev_udn =~ s/:/-/g;
	
	my $filename_body = $dev_friendlyname . "_" . $dev_udn . "_" . $objid;
	$filename_body =~ s/ //g;
	$filename_body =~ s/\//-/g;
	
	my $mpeg2_file_name = $filename_body . ".mpeg";
	my $mpeg4_file_name = $filename_body . "_" . $mp4_format . ".m4v";
	my $output_mpeg4_file_name = $base_directory . $mpeg4_file_name;
```

**Item title and filename preserved** — `examples/dms2vodcast.pl:321-327`

Converted item info stores the same remote title and derived filename.

```perl
	my %info = (
		'objid' => $objid,
		'title' => $title,
		'file_name' => $mpeg4_file_name,
		'file_size' => $mpeg4_file_size,
	);
	
```

**Raw XML heredoc interpolation** — `examples/dms2vodcast.pl:205-220`

Title becomes element content and the link becomes an attribute without XML escaping.

```perl
	$title = $content->{'title'};	
	$fname = $content->{'file_name'};
	$fsize = $content->{'file_size'};

$mp4_link = $rss_base_url . $fname;
$mp4_item = <<"RSS_MP4_ITEM";
<item>
<title>$title</title>
<guid isPermalink="false">$mp4_link</guid>
<enclosure url="$mp4_link" length="$fsize" type="video/mp4" />
</item>
RSS_MP4_ITEM
	print RSS_FILE $mp4_item;
}

$rss_footer = <<"RSS_FOOTER";
```

#### Reachability

Operator runs dms2vodcast and item conversion succeeds or a corresponding nonempty output file already exists; feed publication/consumption is external. A title containing closing RSS title markup can survive the regex extraction.

Limitations:
- Deployment-specific impact was not verified.

#### Severity

**Low** — Confirmed effect is generated feed integrity loss. Downstream script execution and arbitrary file traversal are not established; successful inclusion is an additional prerequisite.

Automatic processing in a long-running service or demonstrated stronger downstream impact would raise severity; strict process isolation and budgets reduce it.

#### Remediation

Use an XML serializer with automatic text/attribute escaping and generate opaque local filenames rather than embedding device-controlled metadata.

Tests:
- Titles containing angle brackets, ampersands and quotes remain literal XML text.
- Enclosure filenames with quotes cannot create additional attributes/elements.

Preventive controls:
- Centralize and document this boundary's explicit safety invariant.

<a id="finding-7"></a>

### [7] Cyclic media containers cause unbounded recursive traversal

| Field | Value |
| --- | --- |
| Severity | low |
| Confidence | high |
| Confidence rationale | Direct current-source trace establishes input, absent local control and outcome; no live deployment or runtime reproduction was assumed. |
| Category | Unbounded traversal of remote object graph |
| CWE | CWE-674 |
| Affected lines | examples/dms2vodcast.pl:257-264, examples/upnpavchk.pl:49-56, examples/upnpavdump.pl:70-78, lib/Net/UPnP/AV/MediaServer.pm:203-215 |

#### Summary

A MediaServer can return a container referring to the requested ObjectID or an endless chain. The recursive examples repeatedly browse it with no visited set or depth/node/request cap.

#### Root Cause

Remote DIDL container IDs are copied into objects and passed back as ObjectID by every recursive call. None of the three example walkers tracks already-visited containers; dms2vodcast requested_count limits conversions only.

**Remote container identity** — `lib/Net/UPnP/AV/MediaServer.pm:203-215`

Untrusted container IDs are copied directly into Container objects.

```perl
	while ($result =~ m/<container(.*?)<\/container>/sgi) {
		$content = $1;
		$container = Net::UPnP::AV::Container->new();
		if ($content =~ m/id=\"(.*?)\"/si) {
			$container->setid($1);
		}
		if ($content =~ m/<dc:title>(.*)<\/dc:title>/si) {
			$container->settitle($1);
		}
		if ($content =~ m/<dc:date>(.*)<\/dc:date>/si) {
			$container->setdate($1);
		}
		push (@content_list, $container);
```

**Converter recurses without graph budget** — `examples/dms2vodcast.pl:253-265`

Returned container IDs lead to another browse and recursive call, even when already visited.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $objid );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	foreach my $child_content (@child_content_list) {
		parse_content_directory($mediaServer, $child_content);
	}
```

**Checker repeats same traversal** — `examples/upnpavchk.pl:45-57`

The checker similarly browses every child without depth/visited limits.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $id );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	foreach my $child_content (@child_content_list) {
		get_contentlist($mediaServer, $child_content);
	}
```

**Dumper repeats same traversal** — `examples/upnpavdump.pl:66-79`

The dumper grows recursion and indentation for cyclic or arbitrarily deep containers.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $id );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	$indent++;
	foreach my $child_content (@child_content_list) {
		print_content($mediaServer, $child_content, $indent);
	}
```

#### Validation

Parent verified the actual entrypoint, transformation, missing control and sink in current local source.

Validation method: Independent parent static source trace after worker discovery

**Remote container identity** — `lib/Net/UPnP/AV/MediaServer.pm:203-215`

Untrusted container IDs are copied directly into Container objects.

```perl
	while ($result =~ m/<container(.*?)<\/container>/sgi) {
		$content = $1;
		$container = Net::UPnP::AV::Container->new();
		if ($content =~ m/id=\"(.*?)\"/si) {
			$container->setid($1);
		}
		if ($content =~ m/<dc:title>(.*)<\/dc:title>/si) {
			$container->settitle($1);
		}
		if ($content =~ m/<dc:date>(.*)<\/dc:date>/si) {
			$container->setdate($1);
		}
		push (@content_list, $container);
```

**Converter recurses without graph budget** — `examples/dms2vodcast.pl:253-265`

Returned container IDs lead to another browse and recursive call, even when already visited.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $objid );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	foreach my $child_content (@child_content_list) {
		parse_content_directory($mediaServer, $child_content);
	}
```

**Checker repeats same traversal** — `examples/upnpavchk.pl:45-57`

The checker similarly browses every child without depth/visited limits.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $id );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	foreach my $child_content (@child_content_list) {
		get_contentlist($mediaServer, $child_content);
	}
```

**Dumper repeats same traversal** — `examples/upnpavdump.pl:66-79`

The dumper grows recursion and indentation for cyclic or arbitrarily deep containers.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $id );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	$indent++;
	foreach my $child_content (@child_content_list) {
		print_content($mediaServer, $child_content, $indent);
	}
```

Assertions:
- Remote DIDL container IDs are copied into objects and passed back as ObjectID by every recursive call. None of the three example walkers tracks already-visited containers; dms2vodcast requested_count limits conversions only.
- Requires the operator to run a recursive example against an attacker-controlled discoverable MediaServer. Normal library getcontentlist performs one bounded sequence of requests rather than recursive traversal.

Limitations:
- Offline static analysis only; no application code, exploit input or network target executed.

#### Dataflow

MediaServer.pm:203-215 container ID -\> dms2vodcast.pl:257-265 / upnpavchk.pl:49-56 / upnpavdump.pl:70-78 recursively browse with no visited/depth/nodes budget.

**Remote container identity** — `lib/Net/UPnP/AV/MediaServer.pm:203-215`

Untrusted container IDs are copied directly into Container objects.

```perl
	while ($result =~ m/<container(.*?)<\/container>/sgi) {
		$content = $1;
		$container = Net::UPnP::AV::Container->new();
		if ($content =~ m/id=\"(.*?)\"/si) {
			$container->setid($1);
		}
		if ($content =~ m/<dc:title>(.*)<\/dc:title>/si) {
			$container->settitle($1);
		}
		if ($content =~ m/<dc:date>(.*)<\/dc:date>/si) {
			$container->setdate($1);
		}
		push (@content_list, $container);
```

**Converter recurses without graph budget** — `examples/dms2vodcast.pl:253-265`

Returned container IDs lead to another browse and recursive call, even when already visited.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $objid );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	foreach my $child_content (@child_content_list) {
		parse_content_directory($mediaServer, $child_content);
	}
```

**Checker repeats same traversal** — `examples/upnpavchk.pl:45-57`

The checker similarly browses every child without depth/visited limits.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $id );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	foreach my $child_content (@child_content_list) {
		get_contentlist($mediaServer, $child_content);
	}
```

**Dumper repeats same traversal** — `examples/upnpavdump.pl:66-79`

The dumper grows recursion and indentation for cyclic or arbitrarily deep containers.

```perl
	unless ($content->iscontainer()) {
		return;
	}

	my @child_content_list = $mediaServer->getcontentlist(ObjectID => $id );
	
	if (@child_content_list <= 0) {
		return;
	}
	
	$indent++;
	foreach my $child_content (@child_content_list) {
		print_content($mediaServer, $child_content, $indent);
	}
```

#### Reachability

Requires the operator to run a recursive example against an attacker-controlled discoverable MediaServer. Normal library getcontentlist performs one bounded sequence of requests rather than recursive traversal.

Limitations:
- Deployment-specific impact was not verified.

#### Severity

**Low** — Nontermination/resource exhaustion affects explicitly run example clients. This narrower deployment lowers severity despite direct source reachability.

Automatic processing in a long-running service or demonstrated stronger downstream impact would raise severity; strict process isolation and budgets reduce it.

#### Remediation

Track visited IDs per device and bound depth, nodes, requests and elapsed time in all example walkers and repeated POD traversal examples.

Tests:
- Self-referential and two-node container cycles terminate.
- A deep acyclic chain stops at the documented depth/node budget.

Preventive controls:
- Centralize and document this boundary's explicit safety invariant.

## Reviewed Surfaces

| Surface | Risk Area | Outcome | Notes |
| --- | --- | --- | --- |
| Device HTTP responses can stall discovery indefinitely | Missing network transaction deadline | Reported | `search()` synchronously forwards network-selected LOCATION to `post()`. Blocking connect/write/header/body reads have no absolute deadline; the UDP `select` timeout is suspended while `post()` runs. |
| Device HTTP responses can exhaust caller memory | Unbounded response buffering | Reported | `post()` reads complete lines, appends headers and EOF/chunked bodies, and passes peer-selected Content-Length/chunk sizes directly to `read()`. There is no maximum line/header/chunk/body budget before buffering. |
| SSDP responses can trigger blind requests to loopback services | Unrestricted discovery-derived request destination | Reported | `recv()` discards sender provenance; URL-pattern matching is the only destination gate. Parsed host/port/path reach `inet_aton()` and `connect()` without a resolved-address or peer-origin policy. Service endpoint construction likewise accepts absolute cross-origin URLs. |
| Repeated SSDP packets keep discovery running and growing | Missing discovery duration and result budgets | Reported | The full timeout is recomputed for each `select()` iteration rather than measured against a fixed end time. Packet count, fetch count and result count are unbounded, and responses are not deduplicated before fetching/appending. |
| Gateway success responses cause endless mapping enumeration | Peer-controlled enumeration termination | Reported | The unconditional loop stops only on peer-supplied non-200 status, increments the index and pushes every response without an entry or elapsed-time cap. |
| Cyclic media containers cause unbounded recursive traversal | Unbounded traversal of remote object graph | Reported | Remote DIDL container IDs are copied into objects and passed back as ObjectID by every recursive call. None of the three example walkers tracks already-visited containers; dms2vodcast requested_count limits conversions only. |
| Media metadata can alter generated RSS XML structure | Missing XML text and attribute escaping | Reported | SOAP entity-decoded DIDL is regex-extracted rather than validated; its title enters the item info hash unchanged, then a heredoc emits it as XML. Filename substitutions remove slashes/spaces but leave XML-significant quotes and angle brackets. |
| Converter Shell execution boundary | Potential command injection | Needs follow-up | examples/dms2vodcast.pl:6,272-306 imports external Shell and passes remote URL/names in complete option strings. No dependency implementation/version is available offline. Original candidate retained in deferred; no confirmed RCE claim. |
| XML parsing and generic SOAP caller authority | XXE / SOAP injection / authorization | Rejected | Device.pm:90-102, ActionResponse.pm:105-120 and HTTP.pm:188-202 use regex/literal replacements, with no entity resolver; no XXE path. Service.pm:217-245,303-319 lacks XML escaping, but generic caller APIs do not establish a distinct restricted-user authority boundary. Remote service controls itself; no additional privilege crossing established. |
| Unix converter filename traversal | Path traversal | Rejected | examples/dms2vodcast.pl:285-287 replaces every slash, defeating ordinary ../ in remote names. Windows separator behavior and local symlink attacks are not established; no arbitrary file-write claim. |
| Current-source secrets, build, metadata and CI | Credential disclosure / CI authority | No issue found | All 33 tracked current files reviewed including docs, metadata, examples and hidden workflow. No supported embedded credential/private key exposure. .github/workflows/make.yml:6-32 uses ordinary pull_request/build testing, no publication/deployment step; t/UPnP.t:8-9 only loads module. No code execution path found in core modules. |

## Open Questions And Follow Up

- Which Shell.pm version and quoting behavior are used by real dms2vodcast installations?
  - Follow-up prompt: Provide the exact installed Shell.pm implementation/version used with examples/dms2vodcast.pl:294-306, then trace metadata to process execution offline before rating command execution.
- No production deployment or remote device authorization policy was supplied. Impact on specific loopback services and feed consumers remains deployment-dependent.
- Source trace confirms remote values reach Shell command option strings, but Shell.pm is absent from the repository and checked local installations. Exact argument quoting/interpreter behavior remains unverified; command execution is not a confirmed finding.
  - Follow-up prompt: Review deferred unit base-001 and close its stated proof gap.
