# NTLM Authentication Scheme for HTTP
## Disclaimer
The entire following document is copied from:
https://web.archive.org/web/20200724074947/https://www.innovation.ch/personal/ronald/ntlm.html

## Introduction
This is an attempt at documenting the undocumented NTLM authentication scheme used by M$'s browsers, proxies, and servers (MSIE and IIS); this scheme is also sometimes referred to as the NT challenge/response (NTCR) scheme. Most of the info here is derived from three sources (see also the Resources section at the end of this document): Paul Ashton's work on the NTLM security holes, the encryption documentation from Samba, and network snooping. Since most of this info is reverse-engineered it is bound to contain errors; however, at least one client and one server have been implemented according to this data and work successfully in conjunction with M$'s browsers, proxies and servers.

Note that this scheme is not as secure as Digest and some other schemes; it is slightly better than the Basic authentication scheme, however.

Also note that this scheme is not an http authentication scheme - it's a connection authentication scheme which happens to (mis-)use http status codes and headers (and even those incorrectly).

## NTLM Handshake
When a client needs to authenticate itself to a proxy or server using the NTLM scheme then the following 4-way handshake takes place (only parts of the request and status line and the relevant headers are shown here; "C" is the client, "S" the server):
```
    1: C  --> S   GET ...
    
    2: C <--  S   401 Unauthorized
                  WWW-Authenticate: NTLM
    
    3: C  --> S   GET ...
                  Authorization: NTLM <base64-encoded type-1-message>
    
    4: C <--  S   401 Unauthorized
                  WWW-Authenticate: NTLM <base64-encoded type-2-message>
    
    5: C  --> S   GET ...
                  Authorization: NTLM <base64-encoded type-3-message>
    
    6: C <--  S   200 Ok
```
## Messages
The three messages sent in the handshake are binary structures. Each one is described below as a pseudo-C struct and in a memory layout diagram. byte is an 8-bit field; short is a 16-bit field. All fields are unsigned. Numbers are stored in little-endian order. Struct fields named zero contain all zeroes. An array length of "*" indicates a variable length field. Hexadecimal numbers and quoted characters in the comments of the struct indicate fixed values for the given field.

The field flags is presumed to contain flags, but their significance is unknown; the values given are just those found in the packet traces.

### Type-1 Message
This message contains the host name and the NT domain name of the client.
```
    struct {
        byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        byte    type;            // 0x01
        byte    zero[3];
        short   flags;           // 0xb203
        byte    zero[2];

        short   dom_len;         // domain string length
        short   dom_len;         // domain string length
        short   dom_off;         // domain string offset
        byte    zero[2];

        short   host_len;        // host string length
        short   host_len;        // host string length
        short   host_off;        // host string offset (always 0x20)
        byte    zero[2];

        byte    host[*];         // host string (ASCII)
        byte    dom[*];          // domain string (ASCII)
    } type-1-message
                 0       1       2       3
             +-------+-------+-------+-------+
         0:  |  'N'  |  'T'  |  'L'  |  'M'  |
             +-------+-------+-------+-------+
         4:  |  'S'  |  'S'  |  'P'  |   0   |
             +-------+-------+-------+-------+
         8:  |   1   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
        12:  | 0x03  | 0xb2  |   0   |   0   |
             +-------+-------+-------+-------+
        16:  | domain length | domain length |
             +-------+-------+-------+-------+
        20:  | domain offset |   0   |   0   |
             +-------+-------+-------+-------+
        24:  |  host length  |  host length  |
             +-------+-------+-------+-------+
        28:  |  host offset  |   0   |   0   |
             +-------+-------+-------+-------+
        32:  |  host string                  |
             +                               +
             .                               .
             .                               .
             +             +-----------------+
             |             | domain string   |
             +-------------+                 +
             .                               .
             .                               .
             +-------+-------+-------+-------+
```

The host and domain strings are ASCII (or possibly ISO-8859-1), are uppercased, and are not nul-terminated. The host name is only the host name, not the FQDN (e.g. just "GOOFY", not "GOOFY.DISNEY.COM"). The offsets refer to the offset of the specific field within the message, and the lengths are the length of specified field. For example, in the above message host_off = 32 and dom_off = host_off + host_len. Note that the lengths are included twice (for some unfathomable reason).

### Type-2 Message
This message contains the server's NTLM challenge.
```
    struct {
        byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        byte    type;            // 0x02
        byte    zero[7];
        short   msg_len;         // 0x28
        byte    zero[2];
        short   flags;           // 0x8201
        byte    zero[2];

        byte    nonce[8];        // nonce
        byte    zero[8];
    } type-2-message
                 0       1       2       3
             +-------+-------+-------+-------+
         0:  |  'N'  |  'T'  |  'L'  |  'M'  |
             +-------+-------+-------+-------+
         4:  |  'S'  |  'S'  |  'P'  |   0   |
             +-------+-------+-------+-------+
         8:  |   2   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
        12:  |   0   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
        16:  |  message len  |   0   |   0   |
             +-------+-------+-------+-------+
        20:  | 0x01  | 0x82  |   0   |   0   |
             +-------+-------+-------+-------+
        24:  |                               |
             +          server nonce         |
        28:  |                               |
             +-------+-------+-------+-------+
        32:  |   0   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
        36:  |   0   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
```

The nonce is used by the client to create the LanManager and NT responses (see Password Hashes). It is an array of 8 arbitrary bytes. The message length field contains the length of the complete message, which in this case is always 40.

### Type-3 Message
This message contains the username, host name, NT domain name, and the two "responses".
```
    struct {
        byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        byte    type;            // 0x03
        byte    zero[3];

        short   lm_resp_len;     // LanManager response length (always 0x18)
        short   lm_resp_len;     // LanManager response length (always 0x18)
        short   lm_resp_off;     // LanManager response offset
        byte    zero[2];

        short   nt_resp_len;     // NT response length (always 0x18)
        short   nt_resp_len;     // NT response length (always 0x18)
        short   nt_resp_off;     // NT response offset
        byte    zero[2];

        short   dom_len;         // domain string length
        short   dom_len;         // domain string length
        short   dom_off;         // domain string offset (always 0x40)
        byte    zero[2];

        short   user_len;        // username string length
        short   user_len;        // username string length
        short   user_off;        // username string offset
        byte    zero[2];

        short   host_len;        // host string length
        short   host_len;        // host string length
        short   host_off;        // host string offset
        byte    zero[6];

        short   msg_len;         // message length
        byte    zero[2];

        short   flags;           // 0x8201
        byte    zero[2];

        byte    dom[*];          // domain string (unicode UTF-16LE)
        byte    user[*];         // username string (unicode UTF-16LE)
        byte    host[*];         // host string (unicode UTF-16LE)
        byte    lm_resp[*];      // LanManager response
        byte    nt_resp[*];      // NT response
    } type-3-message
                 0       1       2       3
             +-------+-------+-------+-------+
         0:  |  'N'  |  'T'  |  'L'  |  'M'  |
             +-------+-------+-------+-------+
         4:  |  'S'  |  'S'  |  'P'  |   0   |
             +-------+-------+-------+-------+
         8:  |   3   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
        12:  |  LM-resp len  |  LM-Resp len  |
             +-------+-------+-------+-------+
        16:  |  LM-resp off  |   0   |   0   |
             +-------+-------+-------+-------+
        20:  |  NT-resp len  |  NT-Resp len  |
             +-------+-------+-------+-------+
        24:  |  NT-resp off  |   0   |   0   |
             +-------+-------+-------+-------+
        28:  | domain length | domain length |
             +-------+-------+-------+-------+
        32:  | domain offset |   0   |   0   |
             +-------+-------+-------+-------+
        36:  |  user length  |  user length  |
             +-------+-------+-------+-------+
        40:  |  user offset  |   0   |   0   |
             +-------+-------+-------+-------+
        44:  |  host length  |  host length  |
             +-------+-------+-------+-------+
        48:  |  host offset  |   0   |   0   |
             +-------+-------+-------+-------+
        52:  |   0   |   0   |   0   |   0   |
             +-------+-------+-------+-------+
        56:  |  message len  |   0   |   0   |
             +-------+-------+-------+-------+
        60:  | 0x01  | 0x82  |   0   |   0   |
             +-------+-------+-------+-------+
        64:  | domain string                 |
             +                               +
             .                               .
             .                               .
             +           +-------------------+
             |           | user string       |
             +-----------+                   +
             .                               .
             .                               .
             +                 +-------------+
             |                 | host string |
             +-----------------+             +
             .                               .
             .                               .
             +   +---------------------------+
             |   | LanManager-response       |
             +---+                           +
             .                               .
             .                               .
             +            +------------------+
             |            | NT-response      |
             +------------+                  +
             .                               .
             .                               .
             +-------+-------+-------+-------+
```

The host, domain, and username strings are in Unicode (UTF-16, little-endian) and are not nul-terminated; the host and domain names are in upper case. The lengths of the response strings are 24.

## Password Hashes
To calculate the two response strings two password hashes are used: the LanManager password hash and the NT password hash. These are described in detail at the beginning of the Samba ENCRYPTION.html document. However, a few things are not clear (such as what the magic constant for the LanManager hash is), so here is some almost-C code which calculates the two responses. Inputs are passw and nonce, the results are in lm_resp and nt_resp.

```
    /* setup LanManager password */

    char  lm_pw[14];
    int   len = strlen(passw);
    if (len > 14)  len = 14;

    for (idx=0; idx<len; idx++)
        lm_pw[idx] = toupper(passw[idx]);
    for (; idx<14; idx++)
        lm_pw[idx] = 0;


    /* create LanManager hashed password */

    unsigned char magic[] = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
    unsigned char lm_hpw[21];
    des_key_schedule ks;

    setup_des_key(lm_pw, ks);
    des_ecb_encrypt(magic, lm_hpw, ks);

    setup_des_key(lm_pw+7, ks);
    des_ecb_encrypt(magic, lm_hpw+8, ks);

    memset(lm_hpw+16, 0, 5);


    /* create NT hashed password */

    int   len = strlen(passw);
    char  nt_pw[2*len];
    for (idx=0; idx<len; idx++)
    {
        nt_pw[2*idx]   = passw[idx];
        nt_pw[2*idx+1] = 0;
    }

    unsigned char nt_hpw[21];
    MD4_CTX context;
    MD4Init(&context);
    MD4Update(&context, nt_pw, 2*len);
    MD4Final(nt_hpw, &context);

    memset(nt_hpw+16, 0, 5);


    /* create responses */

    unsigned char lm_resp[24], nt_resp[24];
    calc_resp(lm_hpw, nonce, lm_resp);
    calc_resp(nt_hpw, nonce, nt_resp);
```
 Helpers:
```
    /*
     * takes a 21 byte array and treats it as 3 56-bit DES keys. The
     * 8 byte plaintext is encrypted with each key and the resulting 24
     * bytes are stored in the results array.
     */
    void calc_resp(unsigned char *keys, unsigned char *plaintext, unsigned char *results)
    {
        des_key_schedule ks;

        setup_des_key(keys, ks);
        des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) results, ks, DES_ENCRYPT);

        setup_des_key(keys+7, ks);
        des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) (results+8), ks, DES_ENCRYPT);

        setup_des_key(keys+14, ks);
        des_ecb_encrypt((des_cblock*) plaintext, (des_cblock*) (results+16), ks, DES_ENCRYPT);
    }


    /*
     * turns a 56 bit key into the 64 bit, odd parity key and sets the key.
     * The key schedule ks is also set.
     */
    void setup_des_key(unsigned char key_56[], des_key_schedule ks)
    {
        des_cblock key;

        key[0] = key_56[0];
        key[1] = ((key_56[0] << 7) & 0xFF) | (key_56[1] >> 1);
        key[2] = ((key_56[1] << 6) & 0xFF) | (key_56[2] >> 2);
        key[3] = ((key_56[2] << 5) & 0xFF) | (key_56[3] >> 3);
        key[4] = ((key_56[3] << 4) & 0xFF) | (key_56[4] >> 4);
        key[5] = ((key_56[4] << 3) & 0xFF) | (key_56[5] >> 5);
        key[6] = ((key_56[5] << 2) & 0xFF) | (key_56[6] >> 6);
        key[7] =  (key_56[6] << 1) & 0xFF;

        des_set_odd_parity(&key);
        des_set_key(&key, ks);
    }
```

## Keeping the connection alive
As mentioned above, this scheme authenticates connections, not requests. This manifests itself in that the network connection must be kept alive during the second part of the handshake, i.e. between the receiving of the type-2 message from the server (step 4) and the sending of the type-3 message (step 5). Each time the connection is closed this second part (steps 3 through 6) must be repeated over the new connection (i.e. it's not enough to just keep sending the last type-3 message). Also, once the connection is authenticated, the Authorization header need not be sent anymore while the connection stays open, no matter what resource is accessed.

For implementations wishing to work with M$'s software this means that they must make sure they use either HTTP/1.0 keep-alive's or HTTP/1.1 persistent connections, and that they must be prepared to do the second part of the handshake each time the connection was closed and is reopened. Server implementations must also make sure that HTTP/1.0 responses contain a Content-length header (as otherwise the connection must be closed after the response), and that HTTP/1.1 responses either contain a Content-length header or use the chunked transfer encoding.

## Example
Here is an actual example of all the messages. Assume the host name is "LightCity", the NT domain name is "Ursa-Minor", the username is "Zaphod", the password is "Beeblebrox", and the server sends the nonce "SrvNonce". Then the handshake is:
```
    C -> S   GET ...
    
    S -> C   401 Unauthorized
             WWW-Authenticate: NTLM
    
    C -> S   GET ...
             Authorization: NTLM TlRMTVNTUAABAAAAA7IAAAoACgApAAAACQAJACAAAABMSUdIVENJVFlVUlNBLU1JTk9S
    
    S -> C   401 Unauthorized
             WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAACgAAAABggAAU3J2Tm9uY2UAAAAAAAAAAA==
    
    C -> S   GET ...
             Authorization: NTLM TlRMTVNTUAADAAAAGAAYAHIAAAAYABgAigAAABQAFABAAAAADAAMAFQAAAASABIAYAAAAAAAAACiAAAAAYIAAFUAUgBTAEEALQBNAEkATgBPAFIAWgBhAHAAaABvAGQATABJAEcASABUAEMASQBUAFkArYfKbe/jRoW5xDxHeoxC1gBmfWiS5+iX4OAN4xBKG/IFPwfH3agtPEia6YnhsADT
    
    S -> C   200 Ok
```
and the unencoded messages are:

### Type-1 Message:
```
       0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
   0:  4e 54 4c 4d 53 53 50 00 01 00 00 00 03 b2 00 00  "NTLMSSP........."
  10:  0a 00 0a 00 29 00 00 00 09 00 09 00 20 00 00 00  "....)....... ..."
  20:  4c 49 47 48 54 43 49 54 59 55 52 53 41 2d 4d 49  "LIGHTCITYURSA-MI"
  30:  4e 4f 52                                         "NOR"
```
### Type-2 Message:
```
       0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
   0:  4e 54 4c 4d 53 53 50 00 02 00 00 00 00 00 00 00  "NTLMSSP........."
  10:  28 00 00 00 01 82 00 00 53 72 76 4e 6f 6e 63 65  "(.......SrvNonce"
  20:  00 00 00 00 00 00 00 00                          "........"
```

### Type-3 Message:
```
       0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
   0:  4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00  "NTLMSSP........."
  10:  72 00 00 00 18 00 18 00 8a 00 00 00 14 00 14 00  "r..............."
  20:  40 00 00 00 0c 00 0c 00 54 00 00 00 12 00 12 00  "@.......T......."
  30:  60 00 00 00 00 00 00 00 a2 00 00 00 01 82 00 00  "`..............."
  40:  55 00 52 00 53 00 41 00 2d 00 4d 00 49 00 4e 00  "U.R.S.A.-.M.I.N."
  50:  4f 00 52 00 5a 00 61 00 70 00 68 00 6f 00 64 00  "O.R.Z.a.p.h.o.d."
  60:  4c 00 49 00 47 00 48 00 54 00 43 00 49 00 54 00  "L.I.G.H.T.C.I.T."
  70:  59 00 ad 87 ca 6d ef e3 46 85 b9 c4 3c 47 7a 8c  "Y....m..F...<Gz."
  80:  42 d6 00 66 7d 68 92 e7 e8 97 e0 e0 0d e3 10 4a  "B..f}h.........J"
  90:  1b f2 05 3f 07 c7 dd a8 2d 3c 48 9a e9 89 e1 b0  "...?....-<H....."
  a0:  00 d3                                            ".."
```
### For reference, the intermediate hashed passwords are:

lm_hpw (LanManager hashed password):
```
91 90 16 f6 4e c7 b0 0b a2 35 02 8c a5 0c 7a 03 00 00 00 00 00
```
nt_hpw (NT hashed password):
```
8c 1b 59 e3 2e 66 6d ad f1 75 74 5f ad 62 c1 33 00 00 00 00 00
```

## Resources
* LM authentication in SMB/CIFS
http://www.ubiqx.org/cifs/SMB.html#SMB.8.3
* A document on cracking NTLMv2 authentication
http://www.blackhat.com/presentations/win-usa-02/urity-winsec02.ppt
* Squid's NLTM authentication project
http://squid.sourceforge.net/ntlm/
* Encryption description for Samba
http://de.samba.org/samba/ftp/docs/htmldocs/ENCRYPTION.html
* Info on the MSIE security hole
http://oliver.efri.hr/~crv/security/bugs/NT/ie6.html
* FAQ: NT Cryptographic Password Attacks & Defences
http://www.ntbugtraq.com/default.asp?sid=1&pid=47&aid=17
* M$'s hotfix to disable the sending of the LanManager response
ftp://ftp.microsoft.com/bussys/winnt/winnt-public/fixes/usa/NT40/hotfixes-postSP3/lm-fix
* A description of M$'s hotfix
http://www.tryc.on.ca/archives/bugtraq/1997_3/0070.html

## Acknowledgements
Special thanks to the following people who helped with the collection and debugging of the above information:

Jon Lennard
Paul Ashton
Jeremy Allison
