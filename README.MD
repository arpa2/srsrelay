# SRS Relay &mdash; Relaying SMTP with SRS support

> *This is a straightforward, yet very useful wrapper around libsrs2.
> It knows just enough of email protocols to use SRS to wrap and unwrap
> mail addresses.*

The supported protocols SMTP, ESMTP and LMTP all engage in a request-response
interaction.  After one of the responses, a request will start with the
magic words `MAIL FROM:<` as specified in
[Section 3.3](https://tools.ietf.org/html/rfc5321#section-3.3) of
[RFC 5321](https://tools.ietf.org/html/rfc5321).  Similarly for
`RCPT TO:<` on return traffic.

Following either is immediately another `>` to indicate that no bounces
are possible, or the envelope sender address followed by `>`.  It is this
address that is passed into
[libsrs2](https://www.libsrs2.org)
if needed.

No frivolities are permitted in the syntax, simply because the preceding
step should be an MTA, and that is a class of software not known for its
spontaneous wits.  So, we shall enforce the form of the RFC and be a bit
unkind to typing users.


## Packing SRS on Traffic Submission

Whether it is needed during email submission,
is determined by a list of (at least one) domains
on the command line, indicating valid sender domains.  The part after the
last `@` in the envelope sender address should match one of these, in a
case-insensitive manner, if the line is to pass without any processing.

When needed, the part between `<` and `>` is rewritten as provided by
libsrs2.  It will then use the first of the listed domains from the command
line as its substitute envelope sender domain.

This daemon listens to a TCP address and port, and relays the underlying
SMTP, ESMTP or LMTP service to which it creates a slave connection to
another TCP address and port.

Internally, the daemon starts a separate process for each incoming
connection, as is customary for mail handling.  In general, the setup
should be usable for most (if not all) common MTAs, namely as a bump
in the wire towards an upstream mail relay for outgoing traffic.


## Unpacking SRS on Bounce Traffic

When traffic bounces, it can be recognised by its special format,
combined with the locally defined domain name.  In this case, it is
the `RCPT TO:<` prefix that introduces the bounce address.  It is
assumed that only locally generated SRS-addresses are presented to
the unpacking service.

The unpacker listens to another TCP port, though on the same address
as the packer service.  It forwards incoming connections to the same
upload service at the same address and port, because both at times
of packing and unpacking should SRS traffic be externally relayed.

## Two Sides of a Coin

The SRS Relay is a *single* daemon running a *dual* service on different
incoming TCP ports.  To the backend, it uses an upstream SMTP relay for
general routing; this may or may not be the local MTA.

Since email addresses are packed or unpacked, there is less concern
for endless looping than there usually is, even when looping back to
the same MTA:

 1. Unpacking can only be done a limited number of times
 2. Packing is not normally done again by the same host

Longer loops may be dangerous still, but these would occur in the
forward direction, and present a certain problem in any case.

The SRS Relay goes through great lengths to ensure that either both
sides are running, or neither.  So the duality of the service really
brings operational convenience, not less control.  It is considered
a serious bug when one side of the coin terminates while the other
is still active.


## Instructions for Postfix

The SRS Relay presents two SMTP services on different ports, let's
say port 10252 for packing and port 10262 for unpacking, both on
::1 or localhost.  We shall demonstrate for the primary domain
`example.com` and secondary domain `example.org`.

The commandline to do this would be

```
srsrelay ::1 10252 10262 smtp.upstream.isp 25 example.com example.org
```

The relay will load key information from `/etc/postfix/srs-keys`.
Lines in this file provide keys, which you should generate at the
time of installation, for instance with a password generator.

```
cat /dev/urandom | hexdump | head | openssl md5 >> /etc/postfix/srs-keys
```

The file supports comments and empty lines, and `srsrelay` indicates in
syslog how many keys it found in which number of lines.  Please check.
Keep the number of keys low, normally 1 and perhaps temporarily 2 while in
transit, because every key added increases the opportunity of a cracker
to make a good guess, and so of using your SRS setup as an open relay!
One key is required, two are only bearable on a temporary basis and
anyting more is downright risky.

Outgoing traffic is easy to handle, because the SRS Relay checks
if the domain needs SRS treatment.  All you need to setup is

```
relayhost = [::1]:10252
```

There are alternative options, with relays that are specific to a
sender, but these require proper attention to the overriding order.

Incoming traffic that looks like SRS and falls under the primary
domain can be passed under an internal domain without loss of
information, as SRS mapping will remove the domain while unpacking.

An entry like this can be added to a regexp table to be added to the
`recipient_canonical_maps`:

```
/^(SRS[01]=.*)@example\.com$/    ${1}@SRS.emCTfnXjF
```

The extra part makes this a non-existent domain, and difficult to
guess.  Pick your own.

The same domain is now mentioned in the `transport` table:

```
SRS.emCTfnXjF	smtp:[::1]:10262
```


**TODO:** If we fully integrated with Postfix, we might use `postconf` to
download configured values in the configuration file.

**TODO:** We should try to add the SRS Proxy to `master.cf` &mdash; how?


## Concerns and Alternatives

There are issues open for discussion.  Please share your experiences and/or
difficulties, and be clear about their impact in your everyday situation.


### Oversized local parts

SRS expands the local part of an email address.  This part is limited
to 64 characters, and silly bulk mailers may put a complete UUID in there,
consuming most of it.  We've seen examples with 40 characters before, and
77 characters after SRS.

A design alternative could be to put more
information in the domain part, for instance under a dedicated subdomain
for SRS, as in `srs.example.com`, and serve its MX records with a DNS
configuration `*.srs.example.com  IN CNAME  example.com`.  The domain part
can grow to 255 characters, and we can control the subdomain length so
it is possible to always make this work.

Nobody is doing this now, but the SRS form for `mary@example.net` could be
shown as an SRS0 record using

```
mary@AJ0ASMNV9ASJF2LA.example.net.srs0.example.com
```

where `AJ0A` would be a timestamp, and `SMNV9ASJF2LA` is a signature.  This
assumes base32, but domain names may support more compact codecs.  There is
no option for case senstivity though.

This format not being standardised, it is not possible to apply the SRS1
logic when traffic is forwarded multiple times.  In full-blown SRS, there
is a need for two validated mail relays, namely one after the origin and
one before each point that may bounce.  Intermediate nodes can be cut out.

Such a two-step SRS1 address is still of controlled and acceptable size,

```
mary@AJ0BHMAC1JAS2PEE.example.net.AJ0ASMNV9ASJF2LA.example.net.srs1.example.com
```

One might reason that if a result would grow beyond 255 characters, that
opportunistic patterns might be matched, and redirections created.

With the far-reduced risk of too much information in the domain, there
is no real concern for having SRS applied in both domain and user name;
there would simply be more than forwarding steps in a bounce than under
normal applications of SRS.  So, domain-based SRS can be used with or
without the consent of local-part-based SRS.  Note that the schemes are
compatible with the
[libsrs2 API](https://www.libsrs2.org/docs/api.html)
and so it is quite easy to integrate into existing software.  Given that
not every site will have the domains setup, it is advised to not use the
domain form by default; it may however be used when the domain is set to
a wildcard form, like `*.example.com`.  (But a remaininig concern is what
to tackle when reversing a mixed form!)

Note that we get in trouble with space when we apply the local-part form
after the domain form; the SRS domains are simply too long, and this
touches on the general design problem of SRS: domains can be up to 255
characters long, local parts only expand to 64 characters.

It is not yet clear is this model is easier or more difficult to support
in an MTA.  Being able to recognise the domain can be helpful.


### Splitting the Sides of the Coin

The incoming and outgoing SRS services are tightly coupled.  It may be
attractive in some setups to have separate services, and control them
independently.  This will not save any memory, but it might avoid having
services and ports allocated.

The configuration would simply mention a `-` instead of a port and set
a non-existing partner process.

It is certainly doable, but is it useful?


