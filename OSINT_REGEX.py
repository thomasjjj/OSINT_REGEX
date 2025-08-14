import re

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
WEBSITE_RE = re.compile(r"\b(?:https?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b")
TWITTER_HANDLE_RE = re.compile(r"@([A-Za-z0-9_]{1,15})\b")
BTC_WALLET_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
ETH_WALLET_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
MONERO_WALLET_RE = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
DASH_WALLET_RE = re.compile(r"\bX[1-9A-HJ-NP-Za-km-z]{33}\b")
CARDANO_WALLET_RE = re.compile(r"\baddr1[a-z0-9]+\b")
DOGE_WALLET_RE = re.compile(r"\bD[a-zA-Z0-9_.-]{33}\b")
LITECOIN_WALLET_RE = re.compile(r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b")
RIPPLE_WALLET_RE = re.compile(r"\br[0-9a-zA-Z]{33}\b")
STELLAR_WALLET_RE = re.compile(r"\bG[0-9A-Z]{40,60}\b")
TX_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
PRICE_RE = re.compile(
    r"(?:USD|EUR|€|\$)\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})|"
    r"\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?\s?(?:USD|EUR|€|\$)"
)
LATLON_RE = re.compile(
    r"(?<!\d)([-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?))\s*,\s*"
    r"([-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?))(?!\d)"
)
LONG_STRING_RE = re.compile(r"\b[a-zA-Z0-9_.-]{20,}\b")

PATTERNS = {
    "emails": EMAIL_RE,
    "websites": WEBSITE_RE,
    "twitter_handles": TWITTER_HANDLE_RE,
    "btc_wallets": BTC_WALLET_RE,
    "eth_wallets": ETH_WALLET_RE,
    "monero_wallets": MONERO_WALLET_RE,
    "dash_wallets": DASH_WALLET_RE,
    "cardano_wallets": CARDANO_WALLET_RE,
    "doge_wallets": DOGE_WALLET_RE,
    "litecoin_wallets": LITECOIN_WALLET_RE,
    "ripple_wallets": RIPPLE_WALLET_RE,
    "stellar_wallets": STELLAR_WALLET_RE,
    "transaction_hashes": TX_HASH_RE,
    "prices": PRICE_RE,
    "latlon": LATLON_RE,
    "long_strings": LONG_STRING_RE,
}


class OSINTRegex:
    def find(self, pattern_name: str, text: str):
        """Return a list of matches for the given pattern name."""
        pattern = PATTERNS.get(pattern_name)
        if pattern is None:
            raise ValueError(f"Unknown pattern: {pattern_name}")
        return pattern.findall(text)

    def find_emails(self, text):
        """Return a list of email addresses found in the text."""
        return self.find("emails", text)

    def find_websites(self, text):
        """Return a list of website URLs found in the text."""
        return self.find("websites", text)

    def find_twitter_handles(self, text):
        """Return a list of Twitter handles (without @) found in the text."""
        return self.find("twitter_handles", text)

    def find_btc_wallets(self, text):
        """Return a list of Bitcoin wallet addresses found in the text."""
        return self.find("btc_wallets", text)

    def find_eth_wallets(self, text):
        """Return a list of Ethereum wallet addresses found in the text."""
        return self.find("eth_wallets", text)

    def find_monero_wallets(self, text):
        """Return a list of Monero wallet addresses found in the text."""
        return self.find("monero_wallets", text)

    def find_dash_wallets(self, text):
        """Return a list of Dash wallet addresses found in the text."""
        return self.find("dash_wallets", text)

    def find_cardano_wallets(self, text):
        """Return a list of Cardano wallet addresses found in the text."""
        return self.find("cardano_wallets", text)

    def find_doge_wallets(self, text):
        """Return a list of Dogecoin wallet addresses found in the text."""
        return self.find("doge_wallets", text)

    def find_litecoin_wallets(self, text):
        """Return a list of Litecoin wallet addresses found in the text."""
        return self.find("litecoin_wallets", text)

    def find_ripple_wallets(self, text):
        """Return a list of Ripple wallet addresses found in the text."""
        return self.find("ripple_wallets", text)

    def find_stellar_wallets(self, text):
        """Return a list of Stellar wallet addresses found in the text."""
        return self.find("stellar_wallets", text)

    def find_transaction_hashes(self, text):
        """Return a list of 64-character transaction hashes found in the text."""
        return self.find("transaction_hashes", text)

    def find_prices(self, text):
        """Return a list of price expressions (USD, EUR, €, $) found in the text."""
        return self.find("prices", text)

    def find_latlon(self, text):
        """Return a list of (lat, lon) tuples found in the text."""
        return self.find("latlon", text)

    def find_long_strings(self, text):
        """Return a list of long alphanumeric strings (20+ chars) found in the text."""
        return self.find("long_strings", text)

# Example usage
if __name__ == "__main__":
    sample_text = """
    Contact: info@example.com, backup: admin@osintambition.org
    Visit https://www.example.com/about or http://osintambition.org.
    Twitter: @OpenAI, @cyb_detective
    BTC: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
    ETH: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
    """

    osint = OSINTRegex()

    print("Emails:", osint.find_emails(sample_text))
    print("Websites:", osint.find_websites(sample_text))
    print("Twitter Handles:", osint.find_twitter_handles(sample_text))
    print("Bitcoin Wallets:", osint.find_btc_wallets(sample_text))
    print("Ethereum Wallets:", osint.find_eth_wallets(sample_text))
    print("Monero Wallets:", osint.find_monero_wallets(sample_text))
    print("Dash Wallets:", osint.find_dash_wallets(sample_text))
    print("Cardano Wallets:", osint.find_cardano_wallets(sample_text))
    print("Dogecoin Wallets:", osint.find_doge_wallets(sample_text))
    print("Litecoin Wallets:", osint.find_litecoin_wallets(sample_text))
    print("Ripple Wallets:", osint.find_ripple_wallets(sample_text))
    print("Stellar Wallets:", osint.find_stellar_wallets(sample_text))
    print("Transaction Hashes:", osint.find_transaction_hashes(sample_text))
    print("Prices:", osint.find_prices(sample_text))
    print("Lat/Lon pairs:", osint.find_latlon(sample_text))
    print("Long Strings (20+ chars):", osint.find_long_strings(sample_text))
