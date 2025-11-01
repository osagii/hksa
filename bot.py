from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    BasicAuth
)
from aiohttp_socks import ProxyConnector
from fake_useragent import FakeUserAgent
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_hex
from http.cookies import SimpleCookie
from datetime import datetime, timezone, timedelta
from colorama import *
import asyncio, json, re, os, pytz

wib = pytz.timezone('Asia/Jakarta')

class BlockStreet:
    def __init__(self) -> None:
        self.BASE_API = "https://api.blockstreet.money/api"
        self.PAGE_URL = "https://blockstreet.money/"
        self.SITE_KEY = "0x4AAAAAABpfyUqunlqwRBYN"
        # Hardcoded SCTG API key
        self.CAPTCHA_KEY = "995UBiYl9x9oCwTtT3JBEtDTMhrd1gWS"
        self.HEADERS = {}
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.access_tokens = {}
        self.cookie_headers = {}

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}{message}",
            flush=True
        )

    def welcome(self):
        print(
            f"""
        {Fore.GREEN + Style.BRIGHT}BlockStreet {Fore.BLUE + Style.BRIGHT}Auto BOT
            """
            f"""
        {Fore.GREEN + Style.BRIGHT}Rey? {Fore.YELLOW + Style.BRIGHT}<INI WATERMARK>
            """
        )

    def format_seconds(self, seconds):
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
    def load_2captcha_key(self):
        try:
            with open("2captcha_key.txt", 'r') as file:
                captcha_key = file.read().strip()

            return captcha_key
        except Exception as e:
            return None
    
    def load_ref_code(self):
        try:
            with open("ref_code.txt", 'r') as file:
                ref_code = file.read().strip()

            return ref_code
        except Exception as e:
            return None
    
    async def load_proxies(self):
        filename = "proxy.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED + Style.BRIGHT}File {filename} Not Found.{Style.RESET_ALL}")
                return
            with open(filename, 'r') as f:
                self.proxies = [line.strip() for line in f.read().splitlines() if line.strip()]
            
            if not self.proxies:
                self.log(f"{Fore.RED + Style.BRIGHT}No Proxies Found.{Style.RESET_ALL}")
                return

            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Proxies Total  : {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(self.proxies)}{Style.RESET_ALL}"
            )
        
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Failed To Load Proxies: {e}{Style.RESET_ALL}")
            self.proxies = []

    def check_proxy_schemes(self, proxies):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxies.startswith(scheme) for scheme in schemes):
            return proxies
        return f"http://{proxies}"

    def get_next_proxy_for_account(self, account):
        if account not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[account] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.account_proxies[account]

    def rotate_proxy_for_account(self, account):
        if not self.proxies:
            return None
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[account] = proxy
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy
    
    def build_proxy_config(self, proxy=None):
        if not proxy:
            return None, None, None

        if proxy.startswith("socks"):
            connector = ProxyConnector.from_url(proxy)
            return connector, None, None

        elif proxy.startswith("http"):
            match = re.match(r"http://(.*?):(.*?)@(.*)", proxy)
            if match:
                username, password, host_port = match.groups()
                clean_url = f"http://{host_port}"
                auth = BasicAuth(username, password)
                return None, clean_url, auth
            else:
                return None, proxy, None

        raise Exception("Unsupported Proxy Type.")
        
    def generate_account(self):
        try:
            private_key = os.urandom(32).hex()
            account = Account.from_key(private_key)
            address = account.address

            return private_key, address
        except Exception as e:
            return None, None
    
    def generate_payload(self, private_key: str, address: str, signnonce: str):
        try:
            timestamp = datetime.now(timezone.utc)
            issued_at_time = timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            expiration_time = (timestamp + timedelta(minutes=2)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            message = f"blockstreet.money wants you to sign in with your Ethereum account:\n{address}\n\nWelcome to Block Street\n\nURI: https://blockstreet.money\nVersion: 1\nChain ID: 179\nNonce: {signnonce}\nIssued At: {issued_at_time}\nExpiration Time: {expiration_time}"

            encoded_message = encode_defunct(text=message)
            signed_message = Account.sign_message(encoded_message, private_key=private_key)
            signature = to_hex(signed_message.signature)

            return {
                "address": address,
                "nonce": signnonce,
                "signature": signature,
                "chainId": 179,
                "issuedAt": issued_at_time,
                "expirationTime": expiration_time,
                "invite_code": self.REF_CODE
            }
        except Exception as e:
            raise Exception(f"Generate Req Payload Failed: {str(e)}")
        
    def mask_account(self, account):
        try:
            mask_account = account[:6] + '*' * 6 + account[-6:]
            return mask_account
        except Exception as e:
            return None

    def print_question(self):
        while True:
            try:
                print(f"{Fore.WHITE + Style.BRIGHT}1. Run With Proxy{Style.RESET_ALL}")
                print(f"{Fore.WHITE + Style.BRIGHT}2. Run Without Proxy{Style.RESET_ALL}")
                proxy_choice = int(input(f"{Fore.BLUE + Style.BRIGHT}Choose [1/2] -> {Style.RESET_ALL}").strip())

                if proxy_choice in [1, 2]:
                    proxy_type = (
                        "With" if proxy_choice == 1 else 
                        "Without"
                    )
                    print(f"{Fore.GREEN + Style.BRIGHT}Run {proxy_type} Proxy Selected.{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter either 1 or 2.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1 or 2).{Style.RESET_ALL}")

        rotate_proxy = False
        if proxy_choice == 1:
            while True:
                rotate_proxy = input(f"{Fore.BLUE + Style.BRIGHT}Rotate Invalid Proxy? [y/n] -> {Style.RESET_ALL}").strip()

                if rotate_proxy in ["y", "n"]:
                    rotate_proxy = rotate_proxy == "y"
                    break
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter 'y' or 'n'.{Style.RESET_ALL}")

        return proxy_choice, rotate_proxy
    
    async def check_connection(self, proxy_url=None):
        connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
        try:
            async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
                async with session.get(url="https://api.ipify.org?format=json", proxy=proxy, proxy_auth=proxy_auth) as response:
                    response.raise_for_status()
                    return True
        except (Exception, ClientResponseError) as e:
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Connection Not 200 OK {Style.RESET_ALL}"
                f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
            )
        
        return None
    
    async def solve_turnstile(self, page_url: str, site_key: str, retries=5):
        in_url = "https://api.sctg.xyz/in.php"
        res_url = "https://api.sctg.xyz/res.php"
        for attempt in range(retries):
            try:
                async with ClientSession(timeout=ClientTimeout(total=60)) as session:
                    if self.CAPTCHA_KEY is None:
                        self.log(
                            f"{Fore.BLUE + Style.BRIGHT}   Status  : {Style.RESET_ALL}"
                            f"{Fore.YELLOW + Style.BRIGHT}Captcha Key Is None{Style.RESET_ALL}"
                        )
                        return None

                    # Create task (form-encoded) for Cloudflare Turnstile
                    in_data = {
                        "key": self.CAPTCHA_KEY,
                        "method": "turnstile",
                        "pageurl": page_url,
                        "sitekey": site_key,
                    }
                    async with session.post(url=in_url, data=in_data) as response:
                        response.raise_for_status()
                        result_text = (await response.text()).strip()

                        if "|" not in result_text or not result_text.startswith("OK|"):
                            self.log(
                                f"{Fore.BLUE + Style.BRIGHT}   Message : {Style.RESET_ALL}"
                                f"{Fore.YELLOW + Style.BRIGHT}{result_text}{Style.RESET_ALL}"
                            )
                            await asyncio.sleep(5)
                            continue

                        _, task_id = result_text.split("|", 1)
                        self.log(
                            f"{Fore.BLUE + Style.BRIGHT}   Task Id : {Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT}{task_id}{Style.RESET_ALL}"
                        )

                        # Small initial delay then poll for solution
                        await asyncio.sleep(2)
                        not_ready_logs = 0
                        for _ in range(30):
                            poll_url = f"{res_url}?key={self.CAPTCHA_KEY}&id={task_id}"
                            async with session.get(url=poll_url) as res_response:
                                res_response.raise_for_status()
                                res_result_text = (await res_response.text()).strip()

                                if res_result_text == "CAPCHA_NOT_READY":
                                    if not_ready_logs < 2:
                                        self.log(
                                            f"{Fore.BLUE + Style.BRIGHT}   Message : {Style.RESET_ALL}"
                                            f"{Fore.YELLOW + Style.BRIGHT}Captcha Not Ready{Style.RESET_ALL}"
                                        )
                                        not_ready_logs += 1
                                    await asyncio.sleep(2)
                                    continue

                                if "|" in res_result_text and res_result_text.startswith("OK|"):
                                    _, recaptcha_token = res_result_text.split("|", 1)
                                    self.log(
                                        f"{Fore.BLUE + Style.BRIGHT}   Status  : {Style.RESET_ALL}"
                                        f"{Fore.GREEN + Style.BRIGHT}Turnstile Solved Successfully{Style.RESET_ALL}"
                                    )
                                    return recaptcha_token

                                # Unexpected response
                                self.log(
                                    f"{Fore.BLUE + Style.BRIGHT}   Message : {Style.RESET_ALL}"
                                    f"{Fore.YELLOW + Style.BRIGHT}{res_result_text}{Style.RESET_ALL}"
                                )
                                break

            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE + Style.BRIGHT}   Status  : {Style.RESET_ALL}"
                    f"{Fore.RED + Style.BRIGHT}Trunstile Not Solved{Style.RESET_ALL}"
                    f"{Fore.MAGENTA + Style.BRIGHT} - {Style.RESET_ALL}"
                    f"{Fore.YELLOW + Style.BRIGHT}{str(e)}{Style.RESET_ALL}"
                )
                return None
    
    async def sign_nonce(self, address: str, proxy_url=None, retries=5):
        url = f"{self.BASE_API}/account/signnonce"
        headers = {
            **self.HEADERS[address],
            "Cookie": "gfsessionid="
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        result = await response.json()

                        if result.get("code") != 0:
                            await asyncio.sleep(5)
                            continue

                        raw_cookies = response.headers.getall('Set-Cookie', [])
                        if raw_cookies:
                            cookie = SimpleCookie()
                            cookie.load("\n".join(raw_cookies))
                            cookie_string = "; ".join([f"{key}={morsel.value}" for key, morsel in cookie.items()])
                            self.cookie_headers[address] = cookie_string

                        return result
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch Nonce Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def sign_verify(self, private_key: str, address: str, signnonce: str, turnstile_token: str, proxy_url=None, retries=5):
        url = f"{self.BASE_API}/account/signverify"
        data = json.dumps(self.generate_payload(private_key, address, signnonce))
        headers = {
            **self.HEADERS[address],
            "cf-turnstile-response": turnstile_token,
            "Content-Length": str(len(data)),
            "Content-Type": "application/json",
            "Cookie": self.cookie_headers[address]
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, data=data, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        result = await response.json()

                        if result.get("code") != 0:
                            await asyncio.sleep(5)
                            continue

                        raw_cookies = response.headers.getall('Set-Cookie', [])
                        if raw_cookies:
                            cookie = SimpleCookie()
                            cookie.load("\n".join(raw_cookies))
                            cookie_string = "; ".join([f"{key}={morsel.value}" for key, morsel in cookie.items()])
                            self.cookie_headers[address] = cookie_string

                        return result
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Login Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def earn_info(self, address: str, proxy_url=None, retries=5):
        url = f"{self.BASE_API}/earn/info"
        headers = {
            **self.HEADERS[address],
            "Cookie": self.cookie_headers[address]
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        result = await response.json()

                        if result.get("code") != 0:
                            await asyncio.sleep(5)
                            continue
                        return result
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Balance :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch Earning Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def share_result(self, address: str, proxy_url=None, retries=5):
        url = f"{self.BASE_API}/share"
        headers = {
            **self.HEADERS[address],
            "Content-Length": "0",
            "Cookie": self.cookie_headers[address]
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        result = await response.json()

                        if result.get("code") != 0:
                            await asyncio.sleep(5)
                            continue
                        return result
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Share X :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def process_check_connection(self, address: str, use_proxy: bool, rotate_proxy: bool):
        while True:
            proxy = self.get_next_proxy_for_account(address) if use_proxy else None
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Proxy   :{Style.RESET_ALL}"
                f"{Fore.WHITE+Style.BRIGHT} {proxy} {Style.RESET_ALL}"
            )

            is_valid = await self.check_connection(proxy)
            if is_valid: return True

            if rotate_proxy:
                proxy = self.rotate_proxy_for_account(address)
                await asyncio.sleep(1)
                continue

            return False
    
    async def process_user_login(self, private_key: str, address: str, use_proxy: bool, rotate_proxy: bool):
        is_valid = await self.process_check_connection(address, use_proxy, rotate_proxy)
        if is_valid:
            proxy = self.get_next_proxy_for_account(address) if use_proxy else None

            nonce = await self.sign_nonce(address, proxy)
            if not nonce: return False

            if nonce.get("code") != 0:
                message = nonce.get("message")

                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch Nonce Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {message} {Style.RESET_ALL}"
                )
                return False
            
            signnonce = nonce.get("data", {}).get("signnonce")

            self.log(f"{Fore.CYAN+Style.BRIGHT}Captcha :{Style.RESET_ALL}")

            turnstile_token = await self.solve_turnstile(self.PAGE_URL, self.SITE_KEY)
            if not turnstile_token: return False

            verify = await self.sign_verify(private_key, address, signnonce, turnstile_token, proxy)
            if not verify: return False

            if verify.get("code") != 0:
                message = verify.get("message")

                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Login Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {message} {Style.RESET_ALL}"
                )
                return False

            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Status  :{Style.RESET_ALL}"
                f"{Fore.GREEN + Style.BRIGHT} Login Success {Style.RESET_ALL}"
            )

            return True

    async def process_accounts(self, private_key: str, address: str, use_proxy: bool, rotate_proxy: bool):
        logined = await self.process_user_login(private_key, address, use_proxy, rotate_proxy)
        if logined:
            proxy = self.get_next_proxy_for_account(address) if use_proxy else None

            earn = await self.earn_info(address, proxy)
            if earn:
                if earn.get("code") == 0:
                    balance = earn.get("data", {}).get("balance")
                    self.log(
                        f"{Fore.CYAN+Style.BRIGHT}Balance :{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} {balance} BSD {Style.RESET_ALL}"
                    )
                else:
                    message = earn.get("message")
                    self.log(
                        f"{Fore.CYAN+Style.BRIGHT}Balance :{Style.RESET_ALL}"
                        f"{Fore.RED+Style.BRIGHT} Fetch Earning Failed {Style.RESET_ALL}"
                        f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.YELLOW+Style.BRIGHT} {message} {Style.RESET_ALL}"
                    )

            share = await self.share_result(address, proxy)
            if share:
                if share.get("code") == 0:
                    self.log(
                        f"{Fore.CYAN+Style.BRIGHT}Share X :{Style.RESET_ALL}"
                        f"{Fore.GREEN+Style.BRIGHT} Success {Style.RESET_ALL}"
                    )
                else:
                    message = share.get("message")
                    self.log(
                        f"{Fore.CYAN+Style.BRIGHT}Share X :{Style.RESET_ALL}"
                        f"{Fore.RED+Style.BRIGHT} Failed {Style.RESET_ALL}"
                        f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.YELLOW+Style.BRIGHT} {message} {Style.RESET_ALL}"
                    )
            
    async def main(self):
        try:
            ref_counts = int(input(f"{Fore.BLUE + Style.BRIGHT}Enter Ref Count -> {Style.RESET_ALL}"))

            captcha_key = self.load_2captcha_key()
            # Only override if a real key is provided (not placeholder/empty)
            if captcha_key and captcha_key.strip() and captcha_key.strip().lower() != "your_2captcha_key":
                self.CAPTCHA_KEY = captcha_key.strip()

            ref_code = self.load_ref_code()
            if ref_code:
                self.REF_CODE = ref_code

            proxy_choice, rotate_proxy = self.print_question()

            self.clear_terminal()
            self.welcome()
            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Referral Code  : {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{self.REF_CODE}{Style.RESET_ALL}"
            )

            use_proxy = True if proxy_choice == 1 else False
            if use_proxy:
                await self.load_proxies()

            separator = "=" * 25
            for idx in range(ref_counts):
                self.log(
                    f"{Fore.CYAN + Style.BRIGHT}{separator}[{Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT} {idx+1} {Style.RESET_ALL}"
                    f"{Fore.CYAN + Style.BRIGHT}Of{Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT} {ref_counts} {Style.RESET_ALL}"
                    f"{Fore.CYAN + Style.BRIGHT}]{separator}{Style.RESET_ALL}"
                )

                private_key, address = self.generate_account()

                if not private_key or not address:
                    self.log(
                        f"{Fore.CYAN + Style.BRIGHT}Status  :{Style.RESET_ALL}"
                        f"{Fore.RED + Style.BRIGHT} Invalid Private Key or Library Version Not Supported {Style.RESET_ALL}"
                    )
                    continue

                self.HEADERS[address] = {
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                    "Origin": "https://blockstreet.money",
                    "Referer": "https://blockstreet.money/",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-site",
                    "User-Agent": FakeUserAgent().random
                }
                
                await self.process_accounts(private_key, address, use_proxy, rotate_proxy)

                with open("wallets.txt", "a") as f:
                    f.write(private_key + "\n")

            self.log(f"{Fore.CYAN + Style.BRIGHT}={Style.RESET_ALL}"*72)

        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e

if __name__ == "__main__":
    try:
        bot = BlockStreet()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT}[ EXIT ] BlockStreet - BOT{Style.RESET_ALL}                                       "                              
        )
