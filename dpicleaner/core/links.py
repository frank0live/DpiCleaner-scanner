"""Rewrite vless/vmess/trojan/ss config links onto a new address."""

import base64
import json
import urllib.parse


def modify_config_link(config_link, target_ip):
    try:
        if config_link.startswith(("vless://", "trojan://")):
            parsed = urllib.parse.urlparse(config_link)
            user_info = parsed.netloc.split('@')[0]
            port = parsed.netloc.split('@')[1].split(':')[1]
            new_netloc = f"{user_info}@{target_ip}:{port}"
            fragment = parsed.fragment
            new_fragment = f"Clean-{target_ip}" if not fragment else f"{fragment}-Clean-{target_ip}"
            new_uri = parsed._replace(netloc=new_netloc, fragment=new_fragment)
            return urllib.parse.urlunparse(new_uri)

        elif config_link.startswith("vmess://"):
            raw_b64 = config_link.replace("vmess://", "").strip()
            raw_b64 += "=" * ((4 - len(raw_b64) % 4) % 4)
            data = json.loads(base64.b64decode(raw_b64).decode('utf-8'))
            data['add'] = target_ip
            data['ps'] = f"{data.get('ps', 'VMess')}-Clean-{target_ip}"
            new_b64 = base64.b64encode(json.dumps(data).encode('utf-8')).decode('utf-8')
            return f"vmess://{new_b64}"

        elif config_link.startswith("ss://"):
            parsed = urllib.parse.urlparse(config_link)
            netloc = parsed.netloc
            if '@' in netloc:
                userinfo, hostport = netloc.split('@', 1)
                port = hostport.split(':')[1]
                new_netloc = f"{userinfo}@{target_ip}:{port}"
                fragment = parsed.fragment
                new_fragment = f"Clean-{target_ip}" if not fragment else f"{fragment}-Clean-{target_ip}"
                new_uri = parsed._replace(netloc=new_netloc, fragment=new_fragment)
                return urllib.parse.urlunparse(new_uri)
    except Exception:
        pass
    return None
