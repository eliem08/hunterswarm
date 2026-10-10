"""Technology fingerprinting from passive HTTP observations.

PASSIVE-ONLY: reads only response headers and HTML the server
voluntarily sent with its homepage. No probing beyond that single
fetch.
"""

import re

# (header-name, value-pattern, technology label)
_HEADER_SIGS = [
    ("server", r"cloudflare", "Cloudflare"),
    ("server", r"nginx", "nginx"),
    ("server", r"apache", "Apache"),
    ("server", r"Microsoft-IIS", "IIS"),
    ("server", r"openresty", "OpenResty"),
    ("server", r"gws", "Google Frontend"),
    ("server", r"AmazonS3", "Amazon S3"),
    ("server", r"Vercel", "Vercel"),
    ("server", r"netlify", "Netlify"),
    ("server", r"ECS", "Amazon ECS"),
    ("x-powered-by", r"Express", "Express.js"),
    ("x-powered-by", r"PHP", "PHP"),
    ("x-powered-by", r"ASP\.NET", "ASP.NET"),
    ("x-aspnet-version", r".+", "ASP.NET"),
    ("x-generator", r"WordPress", "WordPress"),
    ("x-drupal-cache", r".+", "Drupal"),
]

# (html-pattern, technology label)
_HTML_SIGS = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"Joomla!", "Joomla"),
    (r"/_next/|__NEXT_DATA__", "Next.js"),
    (r"data-drupal-selector|Drupal\.settings", "Drupal"),
    (r"cdn\.shopify\.com|Shopify\.theme", "Shopify"),
    (r"wixstatic|wix\.com", "Wix"),
    (r"webflow", "Webflow"),
    (r"gatsby", "Gatsby"),
    (r"nuxt", "Nuxt.js"),
    (r"csrfmiddlewaretoken|django", "Django"),
    (r"csrf-param|rails", "Ruby on Rails"),
    (r"laravel", "Laravel"),
    (r"astro-", "Astro"),
    (r"svelte", "Svelte"),
    (r"vue", "Vue.js"),
    (r"react", "React"),
    (r"angular", "Angular"),
]


def fingerprint(headers, html):
    """Return a sorted list of detected technology names (may be empty)."""
    found = set()
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    for header, pattern, name in _HEADER_SIGS:
        value = lowered.get(header, "")
        if value and re.search(pattern, value, re.IGNORECASE):
            found.add(name)
    text = html or ""
    for pattern, name in _HTML_SIGS:
        if re.search(pattern, text, re.IGNORECASE):
            found.add(name)
    return sorted(found)


def interesting_headers(headers):
    """Subset of headers worth showing in a report."""
    keep = {
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "via",
        "x-cache",
        "cf-ray",
        "x-amz-cf-id",
    }
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    return {k: v for k, v in lowered.items() if k in keep}
