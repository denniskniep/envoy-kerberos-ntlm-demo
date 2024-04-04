# Summary
Using Envoy as Reverse Proxy to an upstream WebApplication which uses NTLM or Kerberos as HTTP Authentication Method (aka. IWA - Integrated Windows Authentication)

HTTP NTLM/Kerberos authentication method authenticates connections, not requests.
Therefore all client requests must be proxied through the same upstream connection, keeping the authentication context.

The issue which should add this as feature to envoy is not fully solved yet (https://github.com/envoyproxy/envoy/issues/12370).

But there is already a config flag which ensures that upstream connections are not reused by multiple downstream connections.

> If `connection_pool_per_downstream_connection` is `true`, the cluster will use a separate connection pool for every downstream connection

(https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto)

## Testing
Testing that authenticated upstream connections are not used by different clients (downstream connections).

Add `UpstreamConnectionID` to AccessLogs (available with Envoy 1.30):
```
UpstreamConnectionID: "%UPSTREAM_CONNECTION_ID%"
```

Start envoy (Before, you have to adjust the domainnames and the ip to the webapplication of your choice in `envoy/envoy.yaml`)
```
sudo docker-compose up
```

Open incognito window and authenticate with Kerberos/NTLM (generates an authenticated connection)

Then run the following bash script. Expectation is that there is **no** successful (authenticated) response returned.

```
while true; do sleep 1; echo "exec"; curl --insecure -v 'https://iwa.example.com' 2>&1 | grep "200"; done;
```

Negative test: If you set `connection_pool_per_downstream_connection` to `false`, than the bash script will return randomly some successful (authenticated) responses. Because the request will hit occasionally an already authenticated connection, which was created by the incognito window.

## Channel Binding Token
When a webapplication is endlessly prompting for credentials while proxied through envoy and even typing the correct credentials does not help, than its very likely that it uses Channel Binding Tokens (CBT). This is also known as "Extended Protection for Authentication".

A client executes the Kerberos/NTLM authentication through an TLS-channel with the server. The Channel Binding Token is a property of the TLS-channel, and is used to bind the TLS-channel to the Kerberos/NTLM authentication conversation payload.

In the event of a "man-in-the-middle" attack where the TLS-channel is intercepted and modified, the encryption key will not match anymore to the Kerberos/NTLM authentication conversation payload. The server detects this mismatch, indicating something between the web browser and itself. Consequently, Kerberos authentication fails, and users encounter a 401 error response even if the correct credentials were provided.

## Useful Kerberos Commands
* `C:\Windows\System32\klist.exe tickets`
* `C:\Windows\System32\klist.exe purge`
* `C:\Windows\System32\setspn.exe -F -Q HTTP/iwa.example.com`

## References
NTLM:
- https://web.archive.org/web/20200724074947/https://www.innovation.ch/personal/ronald/ntlm.html
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ntht/f09cf6e1-529e-403b-a8a5-7368ee096a6a?redirectedfrom=MSDN

Kerberos: 
- https://web.fe.up.pt/%7Ejmcruz/etc/segur/kerberos/faq.html
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-troubleshooting-guidance

Channel Binding:
- https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-iwa#channel-binding-token
- https://www.msxfaq.de/windows/iis/iis_extended_protection.htm
- https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/extended-protection-for-authentication-overview?WT.mc_id=M365-MVP-6771
- https://datatracker.ietf.org/doc/html/rfc2743#page-16
- https://web.archive.org/web/20101029163626/http://blogs.msdn.com/b/fiddler/archive/2010/10/15/fiddler-https-decryption-and-channel-binding-token-authentication-problems.aspx
- https://web.archive.org/web/20101107100350/http://blogs.technet.com/b/srd/archive/2009/12/08/extended-protection-for-authentication.aspx

Other:
- https://www.chromium.org/developers/design-documents/http-authentication/
- https://datatracker.ietf.org/doc/html/rfc4559

