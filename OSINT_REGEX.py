import re

class OSINTRegex:
    def find_emails(self, text):
        """Return a list of email addresses found in the text."""
        pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        return re.findall(pattern, text)

    def find_websites(self, text):
        """Return a list of website URLs found in the text."""
        pattern = r'\b(?:https?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b'
        return re.findall(pattern, text)

    def find_twitter_handles(self, text):
        """Return a list of Twitter handles (without @) found in the text."""
        pattern = r'@([A-Za-z0-9_]{1,15})\b'
        return re.findall(pattern, text)

    def find_btc_wallets(self, text):
        """Return a list of Bitcoin wallet addresses found in the text."""
        pattern = r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'
        return re.findall(pattern, text)

    def find_eth_wallets(self, text):
        """Return a list of Ethereum wallet addresses found in the text."""
        pattern = r'\b0x[a-fA-F0-9]{40}\b'
        return re.findall(pattern, text)

    def find_monero_wallets(self, text):
        """Return a list of Monero wallet addresses found in the text."""
        pattern = r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
        return re.findall(pattern, text)

    def find_dash_wallets(self, text):
        """Return a list of Dash wallet addresses found in the text."""
        pattern = r'\bX[1-9A-HJ-NP-Za-km-z]{33}\b'
        return re.findall(pattern, text)

    def find_cardano_wallets(self, text):
        """Return a list of Cardano wallet addresses found in the text."""
        pattern = r'\baddr1[a-z0-9]+\b'
        return re.findall(pattern, text)

    def find_doge_wallets(self, text):
        """Return a list of Dogecoin wallet addresses found in the text."""
        pattern = r'\bD[a-zA-Z0-9_.-]{33}\b'
        return re.findall(pattern, text)

    def find_litecoin_wallets(self, text):
        """Return a list of Litecoin wallet addresses found in the text."""
        pattern = r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b'
        return re.findall(pattern, text)

    def find_ripple_wallets(self, text):
        """Return a list of Ripple wallet addresses found in the text."""
        pattern = r'\br[0-9a-zA-Z]{33}\b'
        return re.findall(pattern, text)

    def find_stellar_wallets(self, text):
        """Return a list of Stellar wallet addresses found in the text."""
        pattern = r'\bG[0-9A-Z]{40,60}\b'
        return re.findall(pattern, text)

    def find_transaction_hashes(self, text):
        """Return a list of 64-character transaction hashes found in the text."""
        pattern = r'\b[a-fA-F0-9]{64}\b'
        return re.findall(pattern, text)

    def find_prices(self, text):
        """Return a list of price expressions (USD, EUR, €, $) found in the text."""
        pattern = (
            r'((USD|EUR|€|\$)\s?(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2}))|'
            r'(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?)\s?(USD|EUR|€|\$))'
        )
        return [match[0] for match in re.findall(pattern, text)]

    def find_latlon(self, text):
        """Return a list of (lat, lon) tuples found in the text."""
        pattern = (
            r'(?<!\d)([-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?))\s*,\s*'
            r'([-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?))(?!\d)'
        )
        return re.findall(pattern, text)

    def find_long_strings(self, text):
        """Return a list of long alphanumeric strings (20+ chars) found in the text."""
        pattern = r'\b[a-zA-Z0-9_.-]{20,}\b'
        return re.findall(pattern, text)

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