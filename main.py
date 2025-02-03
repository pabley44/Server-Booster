from email import header
from colorama import *
import datetime, time, requests, json, threading, os, random, httpx, sys
import tls_client
from pathlib import Path
from threading import Thread
import hashlib
from base64 import b64encode
from os import listdir
import pystyle
from pystyle import *
from datetime import timedelta
import websocket


config = json.load(open("config.json", encoding="utf-8"))
client_identifiers = ['safari_ios_16_0', 'safari_ios_15_6', 'safari_ios_15_5', 'safari_16_0', 'safari_15_6_1', 'safari_15_3', 'opera_90', 'opera_89', 'firefox_104', 'firefox_102']
fingerprints = json.load(open("fingerprints.json", encoding="utf-8"))

class vars:
    joins = 0; boosts_done = 0; captcha = 0; success_tokens = []; failed_tokens = []

def get_time_rn():
    date = datetime.datetime.now()
    hour = date.hour
    minute = date.minute
    second = date.second
    timee = "{:02d}:{:02d}:{:02d}".format(hour, minute, second)
    return timee

def validateInvite(invite:str):
    client = httpx.Client()
    if 'type' in client.get(f'https://canary.discord.com/api/v10/invites/{invite}?inputValue={invite}&with_counts=true&with_expiration=true').text:
        return True
    else:
        return False 
    
def get_all_tokens(filename:str):
    all_tokens = []
    for j in open(filename, "r").read().splitlines():
        if ":" in j:
            j = j.split(":")[2]
            all_tokens.append(j)
        else:
            all_tokens.append(j)
 
    return all_tokens

def remove(token: str, filename:str):
    tokens = get_all_tokens(filename)
    tokens.pop(tokens.index(token))
    f = open(filename, "w")
    
    for l in tokens:
        f.write(f"{l}\n")
        
    f.close()

def getproxy(): 
    try:
        proxies = random.choice(open("input/proxies.txt", "r").read().splitlines())
        if ":" in proxies and len(proxies.split(":")) == 4:
            ip, port, user, pw = proxies.split(":")
            return {'http': f'http://{user}:{pw}@{ip}:{port}'}
        else:
            ip, port = proxies.split(":")
            return {'http': f'http://{ip}:{port}'}
    except Exception as e:
        pass

def get_fingerprint(thread):
    try:
        proxies = (random.choice(open("input/proxies.txt", "r").readlines()).strip()
            if len(open("input/proxies.txt", "r").readlines()) != 0
            else None)

        if ":" in proxies and len(proxies.split(":")) == 4:
            ip, port, user, pw = proxies.split(":")
            proxy = f"http://{user}:{pw}@{ip}:{port}"
        else:
            ip, port = proxies.split(":")
            proxy = f"http://{ip}:{port}" 

        fingerprint = httpx.get(f"https://canary.discord.com/api/v10/experiments", proxies=proxy if config['proxyless'] != True else None)
        return fingerprint.json()['fingerprint']
    except Exception as e:
        get_fingerprint(thread)

def get_cookies(x, useragent, thread):
    try:
        proxies = (random.choice(open("input/proxies.txt", "r").readlines()).strip()
            if len(open("input/proxies.txt", "r").readlines()) != 0
            else None)

        if ":" in proxies and len(proxies.split(":")) == 4:
            ip, port, user, pw = proxies.split(":")
            proxy = f"http://{user}:{pw}@{ip}:{port}"
        else:
            ip, port = proxies.split(":")
            proxy = f"http://{ip}:{port}" 

        response = httpx.get('https://canary.discord.com/api/v10/experiments', headers = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US','content-type': 'application/json','origin': 'https://canary.discord.com','referer':'https://canary.discord.com','sec-ch-ua': f'"Google Chrome";v="108", "Chromium";v="108", "Not=A?Brand";v="8"','sec-ch-ua-mobile': '?0','sec-ch-ua-platform': '"Windows"','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.40 Chrome/91.0.4472.164 Electron/13.2.2 Safari/537.36", 'x-debug-options': 'bugReporterEnabled','x-discord-locale': 'en-US','x-super-properties': "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC40MCIsIm9zX3ZlcnNpb24iOiIxMC4wLjIyMDAwIiwib3NfYXJjaCI6Ing2NCIsInN5c3RlbV9sb2NhbGUiOiJzayIsImNsaWVudF9idWlsZF9udW1iZXIiOjk2MzU1LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=="}, proxies=proxy if config['proxyless'] != True else None)
        cookie = f"locale=en; __dcfduid={response.cookies.get('__dcfduid')}; __sdcfduid={response.cookies.get('__sdcfduid')}; __cfruid={response.cookies.get('__cfruid')}"
        return cookie
    except Exception as e:
        get_cookies(x, useragent, thread)

def get_headers(token,thread):
    x = fingerprints[random.randint(0, (len(fingerprints)-1))]['x-super-properties']
    useragent = fingerprints[random.randint(0, (len(fingerprints)-1))]['useragent']
    headers = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'scheme':'https',
        'accept-language': 'en-US',
        'authorization': token,
        'content-type': 'application/json',
        'origin': 'https://canary.discord.com',
        'referer':'https://canary.discord.com',
        'sec-ch-ua': f'"Google Chrome";v="108", "Chromium";v="108", "Not=A?Brand";v="8"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'cookie': get_cookies(x, useragent, thread),
        'sec-fetch-site': 'same-origin',
        'user-agent': "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.40 Chrome/91.0.4472.164 Electron/13.2.2 Safari/537.36",
        'x-context-properties': 'eyJsb2NhdGlvbiI6IkpvaW4gR3VpbGQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6IjY3OTg3NTk0NjU5NzA1NjY4MyIsImxvY2F0aW9uX2NoYW5uZWxfaWQiOiIxMDM1ODkyMzI4ODg5NTk0MDM2IiwibG9jYXRpb25fY2hhbm5lbF90eXBlIjowfQ==',
        'x-debug-options': 'bugReporterEnabled',
        'x-discord-locale': 'en-US',
        'x-super-properties': "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC40MCIsIm9zX3ZlcnNpb24iOiIxMC4wLjIyMDAwIiwib3NfYXJjaCI6Ing2NCIsInN5c3RlbV9sb2NhbGUiOiJzayIsImNsaWVudF9idWlsZF9udW1iZXIiOjk2MzU1LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
        'fingerprint': get_fingerprint(thread)
        
        }
    
    return headers, useragent

class solver():

    def capmonster(rqdata: str, site_key: str, websiteURL: str, useragent: str):
        task_payload = {
        'clientKey': config['capmonster_key'],
        'task': {
            "type"             :"HCaptchaTaskProxyless",
            "isInvisible"      : True,
            "data"             : rqdata,
            "websiteURL"       : websiteURL,
            "websiteKey"       : site_key,
            "userAgent"        : useragent
                        }
        }
        key = None
        with httpx.Client(headers={'content-type': 'application/json', 'accept': 'application/json'}, timeout=30) as client:   
            task_id = client.post(f'https://api.capmonster.cloud/createTask', json=task_payload).json()['taskId']
            get_task_payload = {
                'clientKey': config['solver_key_key'],
                'taskId': task_id,
            }
        

            while key is None:
                response = client.post("https://api.capmonster.cloud/getTaskResult", json = get_task_payload).json()
                if response['status'] == "ready":
                    key = response["solution"]["gRecaptchaResponse"]
                else:
                    time.sleep(1)
            
        return key
    
    def capsolver(rqdata: str, site_key: str, websiteURL: str, useragent: str):
        task_payload = {
        'clientKey': config['solver_key'],
        'task': {
            "type"             :"HCaptchaTaskProxyless",
            "isInvisible"      : True,
            "data"             : rqdata,
            "websiteURL"       : websiteURL,
            "websiteKey"       : site_key,
            "userAgent"        : useragent
                        }
        }
        key = None
        with httpx.Client(headers={'content-type': 'application/json', 'accept': 'application/json'}, timeout=30) as client:   
            task_id = client.post(f'https://api.capsolver.com/createTask', json=task_payload).json()['taskId']
            get_task_payload = {
                'clientKey': config['capmonster_key'],
                'taskId': task_id,
            }
        

            while key is None:
                response = client.post("https://api.capsolver.com/getResult", json = get_task_payload).json()
                if response['status'] == "ready":
                    key = response["solution"]["gRecaptchaResponse"]
                else:
                    time.sleep(1)
            
        return key

def join_server(session, headers, useragent, invite, token, thread):
    join_outcome = False
    guild_id = 0
    time_rn = get_time_rn()
    try:
        for i in range(10):
            response = session.post(f'https://canary.discord.com/api/v9/invites/{invite}', json={}, headers = headers)
            if response.status_code == 429:
                print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Your IP has been ratelimited! Sleeping for 5 seconds. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                time.sleep(5)
                join_server(session, headers, useragent, invite, token)
                
            elif response.status_code in [200, 204]:
                join_outcome = True
                guild_id = response.json()["guild"]["id"]
                break
            elif "captcha_rqdata" in response.text:
                print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Solving captcha. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                r = response.json()
                solution = get_captcha_key(rqdata = r['captcha_rqdata'], site_key = r['captcha_sitekey'], websiteURL = "https://discord.com", useragent = useragent)
                response = session.post(f'https://canary.discord.com/api/v9/invites/{invite}', json={'captcha_key': solution,'captcha_rqtoken': r['captcha_rqtoken']}, headers = headers)
                if response.status_code in [200, 204]:
                    join_outcome = True
                    guild_id = response.json()["guild"]["id"]
                    break
                    
        return join_outcome, guild_id

            
    except Exception as e:
        join_server(session, headers, useragent, invite, token, thread)

def put_boost(session, headers, guild_id, boost_id):
    try:
        payload = {"user_premium_guild_subscription_slot_ids": [boost_id]}
        boosted = session.put(f"https://canary.discord.com/api/v9/guilds/{guild_id}/premium/subscriptions", json=payload, headers=headers)
        if boosted.status_code == 201:
            return True
        elif 'Must wait for premium server subscription cooldown to expire' in boosted.text:
            return False
    except Exception as e:
        put_boost(session, headers, guild_id, boost_id)

    def online():
        ws = websocket.WebSocket()
        ws.connect("wss://gateway.discord.gg/?encoding=json&v=9")
        response = ws.recv()
        event = json.loads(response)
        heartbeat_interval = int(event["d"]["heartbeat_interval"]) / 1000
        statuses = ["online", "idle", "dnd"]
        ws.send(
                json.dumps(
                            {
                                "op": 2,
                                "d": {
                                    "token": token,
                                    "properties": {
                                        "$os": sys.platform,
                                        "$browser": "RTB",
                                        "$device": f"{sys.platform} Device",
                                    },
                                    "presence": {
                                        "game": {
                                            "name": config["name"],
                                            "type": 0,
                                            "details": config["details"],
                                            "state": config["state"],
                                        },
                                        "status": random.choice(statuses),
                                        "since": 0,
                                        "activities": [],
                                        "afk": False,
                                    },
                                },
                                "s": None,
                            "t": None,
                            }
                        )
                    )

        while True:
                heartbeatJSON = {
                            "op": 1, 
                            "token": token, 
                            "d": "null"
                        }
                ws.send(json.dumps(heartbeatJSON))
                time.sleep(heartbeat_interval)


                for token in open("./tokens.txt", "r").read().splitlines():
                    threading.Thread(target=online).start()

def change_guild_name(session, headers, server_id, nick):
    try:
        jsonPayload = {"nick": nick}
        r = session.patch(f"https://canary.discord.com/api/v9/guilds/{server_id}/members/@me", headers=headers, json=jsonPayload)
        if r.status_code == 200:
            return True
        else:
            return False
        
    except Exception as e:
        change_guild_name(session, headers, server_id, nick)

def change_guild_bio(session, headers, server_id, bio):
    try:
        jsonPayload = {"bio": bio}
        r = session.patch(f"https://canary.discord.com/api/v9/guilds/{server_id}/members/@me", headers=headers, json=jsonPayload)
        if r.status_code == 200:
            return True
        else:
            return False
        
    except Exception as e:
        change_guild_name(session, headers, server_id, bio)

def change_guild_pfp(session, headers, server_id):
    try:
        pfps = "input/data/pfp"
        with open(pfps + random.choice(listdir(pfps)), "rb") as f:
            img = f.read()
        r = session.patch('https://discord.com/api/v10/users/@me', json={"avatar":f'data:image/png;base64,{b64encode(img).decode("ascii")}'})
        if r.status_code == 200:
            return True
        else:
            return False
        
    except Exception as e:
        change_guild_pfp(session, headers, server_id)

def change_guild_banner(session, headers, server_id):
    try:
        banners = "input/data/banners"
        with open(banners + random.choice(listdir(banners)), "rb") as f:
            img = f.read()
        r = session.patch('https://discord.com/api/v10/users/@me', json={"banner":f'data:image/png;base64,{b64encode(img).decode("ascii")}'})
        if r.status_code == 200:
            return True
        else:
            return False
        
    except Exception as e:
        change_guild_banner(session, headers, server_id)

def boost_server(invite:str , months:int, token:str, thread:int, nick: str, bio: str):
    if months == 1:
        filename = "input/1m_tokens.txt"
    if months == 3:
        filename = "input/3m_tokens.txt"

    try:
        time_rn = get_time_rn()
        session = tls_client.Session(ja3_string = fingerprints[random.randint(0, (len(fingerprints)-1))]['ja3'], client_identifier = random.choice(client_identifiers))
        if config['proxyless'] == False and len(open("Input/proxies.txt", "r").readlines()) != 0:
            proxy = getproxy()
            session.proxies.update(proxy)

        headers, useragent = get_headers(token, thread)
        boost_data = session.get(f"https://canary.discord.com/api/v9/users/@me/guilds/premium/subscription-slots", headers=headers)
        if "401: Unauthorized" in boost_data.text:
            print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Invalid token. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
            vars.failed_tokens.append(token)
            remove(token, filename)

        if "You need to verify your account in order to perform this action." in boost_data.text:
            print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Locked token. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
            vars.failed_tokens.append(token)
            remove(token, filename)

        if boost_data.status_code == 200:
            if len(boost_data.json()) != 0:
                join_outcome, guild_id = join_server(session, headers, useragent, invite, token, thread)
                if join_outcome:
                    print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTGREEN_EX}INF {Fore.LIGHTBLACK_EX}> {Fore.RESET}Successfully joined server. {Fore.LIGHTBLACK_EX}server-id={Fore.RESET}{guild_id} {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                    for boost in boost_data.json():
                        boost_id = boost["id"]
                        boosted = put_boost(session, headers, guild_id, boost_id)
                        if boosted:
                            print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTGREEN_EX}INF {Fore.LIGHTBLACK_EX}> {Fore.RESET}Successfully Boosted server. {Fore.LIGHTBLACK_EX}server-id={Fore.RESET}{guild_id} {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                            vars.boosts_done += 1
                            if token not in vars.success_tokens:
                                vars.success_tokens.append(token)    
                        else:
                            print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Error boosting! {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                            if token not in vars.failed_tokens:
                                vars.failed_tokens.append(token)
                    remove(token, filename)

                    changed = change_guild_name(session, headers, guild_id, nick)
                    if changed:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTGREEN_EX}INF {Fore.LIGHTBLACK_EX}> {Fore.RESET}Successfully changed name. {Fore.LIGHTBLACK_EX}nick={Fore.RESET}{nick} {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                    else:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Error renaming. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                    
                    changed = change_guild_bio(session, headers, guild_id, bio)
                    if changed:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTGREEN_EX}INF {Fore.LIGHTBLACK_EX}> {Fore.RESET}Successfully changed bio. {Fore.LIGHTBLACK_EX}bio={Fore.RESET}['{bio}'] {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                    else:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Error when changing bio. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")

                    changed = change_guild_pfp(session, headers, guild_id)
                    if changed:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTGREEN_EX}INF {Fore.LIGHTBLACK_EX}> {Fore.RESET}Successfully changed avatar. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                    else:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Error when changing avatar. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")

                    changed = change_guild_banner(session, headers, guild_id)
                    if changed:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTGREEN_EX}INF {Fore.LIGHTBLACK_EX}> {Fore.RESET}Successfully changed banner. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                    else:
                        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Error when changing banner. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                else:
                    print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Error when joining server. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                    remove(token, filename)
                    vars.failed_tokens.append(token)
            else:
                remove(token, filename)
                print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}No nitro. {Fore.LIGHTBLACK_EX}token={Fore.RESET}{token}")
                vars.failed_tokens.append(token)

    except Exception as e:
        boost_server(invite, months, token, thread, nick, bio)

def thread_boost(invite, amount, months, nick, bio):
    vars.boosts_done = 0
    vars.success_tokens = []
    vars.failed_tokens = []
    time_rn = get_time_rn()

    if months == 1:
        filename = "Input/1m_tokens.txt"
    if months == 3:
        filename = "Input/3m_tokens.txt"
    
    if validateInvite(invite) == False:
        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Invalid invite!")
        return False
        
    while vars.boosts_done != amount:
        print()
        tokens = get_all_tokens(filename)
        
        if vars.boosts_done % 2 != 0:
            vars.boosts_done -= 1
            
        numTokens = int((amount - vars.boosts_done)/2)
        if len(tokens) == 0 or len(tokens) < numTokens:
            print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Not enough {months} month(s) tokens in stock to start!")
            return False
        
        else:
            threads = []
            for i in range(numTokens):
                token = tokens[i]
                thread = i+1
                t = threading.Thread(target=boost_server, args=(invite, months, token, thread, nick, bio))
                t.daemon = True
                threads.append(t)
                
            for i in range(numTokens):
                threads[i].start()
                
            for i in range(numTokens):
                threads[i].join()

            
    return True

def auth():
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                         █   █ █▀▀ █▀▀▄ █▀▀▄ █▀▀ ▀▀█▀▀ ▀▀█▀▀ █▀▀█ 　 ▀█▀ █▀▀▄ █▀▀▄ █▀▀█ ▀█ █▀ █▀▀█ ▀▀█▀▀  ▀  █▀▀█ █▀▀▄ █▀▀\n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                          █ █  █▀▀ █  █ █  █ █▀▀   █     █   █▄▄█ 　  █  █  █ █  █ █  █  █▄█  █▄▄█   █   ▀█▀ █  █ █  █ ▀▀█\n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                          ▀▄▀  ▀▀▀ ▀  ▀ ▀▀▀  ▀▀▀   ▀     ▀   ▀  ▀ 　 ▄█▄ ▀  ▀ ▀  ▀ ▀▀▀▀   ▀   ▀  ▀   ▀   ▀▀▀ ▀▀▀▀ ▀  ▀ ▀▀▀\n", 1))
    print("")
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                                       #1 Boosting Tool\n", 1))
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    time_rn = get_time_rn()
    os.system("cls")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                        █ █ █ █▀▀ █   █▀▀ █▀█ █▀▄▀█ █▀▀\n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                        ▀▄▀▄▀ ██▄ █▄▄ █▄▄ █▄█ █ ▀ █ ██▄\n", 1))
    print("")
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                                #1 Boosting Tool\n", 1))
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    print("")
    time.sleep(2)
    os.system("cls")
    time.sleep(2)
    menu()
    
def menu():
    os.system("cls")
    os.system(f"title Boost Tool ・ discord")
    time_rn = get_time_rn()
    print("")
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                ▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄       ▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄ ▄▄▄     ▄▄▄     ▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ \n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                               █       █ █       █     █       █        █   █   █   █   █   █  █  █ █       █\n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                               █  ▄▄▄▄▄█ █  ▄▄▄▄▄█     █  ▄▄▄▄▄█     ▄▄▄█   █   █   █   █   █   █▄█ █   ▄▄▄▄█\n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                               █ █▄▄▄▄▄█ █ █▄▄▄▄▄█     █ █▄▄▄▄▄█    █▄▄▄█   █   █   █   █   █       █  █  ▄▄ \n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                               █▄▄▄▄▄  █ █▄▄▄▄▄  █     █▄▄▄▄▄  █     ▄▄▄█   █▄▄▄█   █▄▄▄█   █  ▄    █  █ █  █\n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                               ▄▄▄▄▄█  █ ▄▄▄▄▄█  █     ▄▄▄▄▄█  █    █▄▄▄█       █       █   █ █ █   █  █▄▄█ █\n", 1))
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                               █▄▄▄▄▄▄▄█ █▄▄▄▄▄▄▄█     █▄▄▄▄▄▄▄█ ▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄█▄█  █▄▄█▄▄▄▄▄▄▄█\n", 1))
    print("")
    print(Colorate.Horizontal(Colors.cyan_to_blue, "                                                 #1 Boosting Tool | pablo industries \n", 1))
    print("")
    print("")
    invite = input(f"{Style.BRIGHT}{Fore.LIGHTCYAN_EX}[?]{Fore.RESET}{Style.RESET_ALL} Invite: discord.gg/")
    if ".gg/" in invite:
        invite = str(invite).split(".gg/")[1]
    elif "invite/" in invite:
        invite = str(invite).split("invite/")[1]
    if (
        '{"message": "Unknown Invite", "code": 10006}'
        in httpx.get(f"https://canary.discord.com/api/v9/invites/{invite}").text):
        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Invalid invite!")
        return
    
    try:
        months = int(input(f"{Style.BRIGHT}{Fore.LIGHTCYAN_EX}[?]{Fore.RESET}{Style.RESET_ALL} Months: "))
    except:
        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Months can be 1 or 3 only!")
        time.sleep(1)
        menu()
        return
    if months != 1 and months != 3:
        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Months can be 1 or 3 only!")
        time.sleep(1)
        menu()
        return
    
    try:
        amount = input(f"{Style.BRIGHT}{Fore.LIGHTCYAN_EX}[?]{Fore.RESET}{Style.RESET_ALL} Amount: ")
    except:
        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Amount must be Even!")
        time.sleep(1)
        menu()
        return
    amount = int(amount)
    if amount % 2 != 0:
        print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTRED_EX}WRN {Fore.LIGHTBLACK_EX}> {Fore.RESET}Amount must be Even!")
        time.sleep(1)
        menu()
        return
    
    nick = input(f"{Style.BRIGHT}{Fore.LIGHTCYAN_EX}[?]{Fore.RESET}{Style.RESET_ALL} Nick: ")
    bio = input(f"{Style.BRIGHT}{Fore.LIGHTCYAN_EX}[?]{Fore.RESET}{Style.RESET_ALL} Bio: ")
    go = time.time()
    thread_boost(invite, amount, months, nick, bio)
    end = time.time()
    time_went = round(end - go, 5)
    print()
    print(f"{Fore.LIGHTBLACK_EX}{time_rn}{Fore.RESET} {Fore.LIGHTGREEN_EX}INF {Fore.LIGHTBLACK_EX}> {Fore.RESET}Successfully boosted discord.gg/{invite}, {len(vars.success_tokens)*2} times in {time_went} seconds.")
    input("")
    os.system("cls")
    menu()

auth()