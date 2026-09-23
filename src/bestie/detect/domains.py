"""Offline domain knowledge: TLDs, multi-tenant platforms, and public suffixes."""

from __future__ import annotations

# Generic TLDs commonly seen in logs and threat intel. Every two-letter
# alphabetic label is also accepted as a country-code TLD.
GENERIC_TLDS = frozenset(
    """
    com net org edu gov mil int info biz name pro mobi aero asia coop museum jobs travel tel
    io ai app dev xyz top site online club shop store tech cloud live me tv cc blog page
    icu buzz vip work fun space website host press rest win bid loan date download racing
    review stream party trade science men cam lol mom quest sbs cfd bond cyou monster beauty
    hair link click one world today news email network digital agency solutions services
    systems support center company group global zone city life center moe ninja rocks
    tools best money finance bank cash credit capital exchange market markets plus
    zip mov run wiki social chat studio design media video games game bet casino poker
    red blue pink black green gold icu locker onion
    local lan internal corp home intranet localdomain private
    """.split()
)

# Two-label names ending in these are almost always file names (setup.py, a.zip).
FILE_EXTENSIONS = frozenset(
    """
    py sh md rs js ts cs go pl pm rb db gz xz bz zip mov rar tar json yaml yml xml html htm
    css txt log csv exe dll sys bat cmd ps ps1 psm1 vbs hta lnk msi iso img bin dat tmp bak
    cfg conf ini doc docx xls xlsx ppt pptx pdf rtf png jpg jpeg gif bmp mp mp3 mp4 wav so
    ko jar war class java cpp hpp cc h c php asp aspx jsp sql lua r kt swift toml lock pyc
    """.split()
)

# Multi-tenant platforms: the tenant label identifies your org (acme.sharepoint.com)
# or the attacker's infrastructure, but the platform is useful context. We keep the
# suffix and mask the tenant: acme.sharepoint.com -> DOMAIN_003.sharepoint.com
PLATFORM_SUFFIXES = (
    "sharepoint.com",
    "onmicrosoft.com",
    "azurewebsites.net",
    "blob.core.windows.net",
    "file.core.windows.net",
    "queue.core.windows.net",
    "table.core.windows.net",
    "vault.azure.net",
    "database.windows.net",
    "cloudapp.net",
    "cloudapp.azure.com",
    "azureedge.net",
    "trafficmanager.net",
    "servicebus.windows.net",
    "amazonaws.com",
    "cloudfront.net",
    "elasticbeanstalk.com",
    "awsapps.com",
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "appspot.com",
    "firebaseapp.com",
    "web.app",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "loca.lt",
    "duckdns.org",
    "no-ip.org",
    "ddns.net",
    "hopto.org",
    "zapto.org",
    "atlassian.net",
    "slack.com",
    "zendesk.com",
    "okta.com",
    "oktapreview.com",
    "service-now.com",
    "my.salesforce.com",
    "force.com",
    "webex.com",
    "zoom.us",
    "myshopify.com",
    "box.com",
    "notion.site",
    "wordpress.com",
    "blogspot.com",
)

# Well-known public domains that are useful context and not sensitive.
# Subdomains are allowed too (login.microsoftonline.com).
DEFAULT_ALLOWED_DOMAINS = (
    "microsoft.com",
    "microsoftonline.com",
    "windows.com",
    "windowsupdate.com",
    "windows.net",
    "office.com",
    "office365.com",
    "live.com",
    "outlook.com",
    "msn.com",
    "bing.com",
    "msftncsi.com",
    "msedge.net",
    "azure.com",
    "visualstudio.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "gmail.com",
    "youtube.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "cloudflare.com",
    "akamai.net",
    "akamaihd.net",
    "akamaiedge.net",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "digicert.com",
    "letsencrypt.org",
    "mozilla.org",
    "ubuntu.com",
    "debian.org",
    "python.org",
    "pypi.org",
    "npmjs.com",
    "npmjs.org",
    "docker.com",
    "docker.io",
    "mitre.org",
    "virustotal.com",
    "abuse.ch",
    "shodan.io",
    "cisa.gov",
    "nist.gov",
    "anthropic.com",
    "claude.ai",
    "openai.com",
    "example.com",
    "example.net",
    "example.org",
    "example",
    "localhost",
    "localdomain",
)

# Second-level public suffixes, so registrable domains split correctly.
SECOND_LEVEL_SUFFIXES = frozenset(
    """
    co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk com.au net.au org.au gov.au edu.au
    co.jp ne.jp or.jp com.br net.br gov.br co.in net.in org.in gov.in co.za org.za
    com.mx gob.mx com.cn net.cn org.cn gov.cn com.tr gov.tr co.kr or.kr com.ar gob.ar
    com.sg gov.sg com.hk com.tw co.nz org.nz co.il gov.il com.es com.pl co.id com.my
    com.ph com.vn com.sa com.eg com.co com.pe com.ve com.ua co.th
    """.split()
)


def is_tld(label: str) -> bool:
    label = label.lower()
    return label in GENERIC_TLDS or (len(label) == 2 and label.isalpha())


def registrable_split(domain: str) -> tuple[str, str]:
    """Split ``cdn.evil.co.uk`` into (``cdn``, ``evil.co.uk``)."""
    labels = domain.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]).lower() in SECOND_LEVEL_SUFFIXES else 2
    if len(labels) <= n:
        return "", domain
    return ".".join(labels[:-n]), ".".join(labels[-n:])
