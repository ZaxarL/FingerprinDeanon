from django.shortcuts import render, redirect
import fingerprint
from django.http import HttpResponseRedirect, HttpResponse
import requests
from .models import UserInfo

# Create your views here.
def check_TOR(user_ip):
    TOR_IPS_LINK = "https://check.torproject.org/torbulkexitlist"
    try:
        response = requests.get(TOR_IPS_LINK)
    except requests.HTTPError as http_err:
        print(f"HTTP error: {http_err}")
    except Exception as exc:
        print(f"Error: {exc}")
    tor_ip = response.text.split('\n')
    if user_ip in tor_ip:
        return True
    return False


def check_VPN(user_ip):
    VPN_IPS_LINK = "https://hidemy.life/api/vpn.json"
    try:
        response = requests.get(VPN_IPS_LINK)
    except requests.HTTPError as http_err:
        print(f"HTTP error: {http_err}")
    except Exception as exc:
        print(f"Error: {exc}")
    #print(response.text)
    vpn_ip = response.json()['list']
    #print(type(vpn_ip))
    if user_ip in vpn_ip:
        return True
    return False


def check_proxy(request):
    PROXYHEADERS = ["HTTP_VIA", "HTTP_X_FORWARDED_FOR", "HTTP_FORWARDED_FOR", "HTTP_X_FORWARDED",
     "HTTP_FORWARDED", "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR_IP", "VIA", "X_FORWARDED_FOR", "FORWARDED_FOR",
     "X_FORWARDED", "FORWARDED", "CLIENT_IP", "FORWARDED_FOR_IP", "HTTP_PROXY_CONNECTION"]
    #print(request.headers)
    res = []
    for head in PROXYHEADERS:
        if head in request.headers:
            print(request.headers[head])
            res.append(request.headers[head])
    if res:
        return True, res
    return False, res


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def check_user(fp, hash_fp, hash_canvas_fp, user_ip):
    try:
        user_info = UserInfo.objects.get(visitorId=fp['visitorId'])
    except UserInfo.DoesNotExist:
        try:
            user_info = UserInfo.objects.get(hash_fingerprint=hash_fp)
        except UserInfo.DoesNotExist:
            try:
                user_info = UserInfo.objects.get(hash_canvas_fingerprint=hash_canvas_fp)
            except UserInfo.DoesNotExist:
                try:
                    user_info = UserInfo.objects.get(user_ip=user_ip)
                except UserInfo.DoesNotExist:
                    return True
                else:
                    if user_info.hash_canvas_fingerprint != hash_canvas_fp or user_info.visitorId != fp['visitorId'] or user_info.hash_fingerprint != hash_fp:
                        user = UserInfo(visitorId=fp['visitorId'], hash_fingerprint=hash_fp,
                                        hash_canvas_fingerprint=hash_canvas_fp,
                                        user_ip=user_ip)
                        user.save()
                    print("user_ip: {}".format(user_ip))
                    return False
            else:
                if user_info.user_ip != user_ip or user_info.visitorId != fp['visitorId'] or user_info.hash_fingerprint != hash_fp:
                    user = UserInfo(visitorId=fp['visitorId'], hash_fingerprint=hash_fp,
                                    hash_canvas_fingerprint=hash_canvas_fp,
                                    user_ip=user_ip)
                    user.save()
                print("hash_canvas_fingerprint: {}".format(hash_canvas_fp))
                return False
        else:
            if user_info.user_ip != user_ip or user_info.visitorId != fp['visitorId'] or user_info.hash_canvas_fingerprint != hash_canvas_fp:
                user = UserInfo(visitorId=fp['visitorId'], hash_fingerprint=hash_fp,
                                hash_canvas_fingerprint=hash_canvas_fp,
                                user_ip=user_ip)
                user.save()
            print("hash_fingerprint: {}".format(fp['hash_fingerprint']))
            return False
    else:
        if user_info.user_ip != user_ip or user_info.hash_fingerprint != hash_fp or user_info.hash_canvas_fingerprint != hash_canvas_fp:
            user = UserInfo(visitorId=fp['visitorId'], hash_fingerprint=hash_fp, hash_canvas_fingerprint=hash_canvas_fp,
                            user_ip=user_ip)
            user.save()
        print("visitorId: {}".format(fp['visitorId']))
        return False


def new_user(fp, hash_fp, hash_canvas_fp, user_ip):
    user = UserInfo(visitorId=fp['visitorId'], hash_fingerprint=hash_fp, hash_canvas_fingerprint=hash_canvas_fp,
                    user_ip=user_ip)
    user.save()


def login(request):
    if request.method == 'POST':
        user_ip = get_client_ip(request)
        flag_tor = check_TOR(user_ip)
        flag_vpn = check_VPN(user_ip)
        flag_proxy, proxy_header = check_proxy(request)
        # Getting a fingerprint
        try:
            fp, hash_fp, hash_canvas_fp = fingerprint.fingerprint.get(request)
        except ConnectionError:
            return HttpResponse("Can't get fingerprint")
        except ValueError:
            return HttpResponse("Value error")
        flag_new_user = check_user(fp, hash_fp, hash_canvas_fp, user_ip)
        if flag_new_user:
            if flag_tor or flag_vpn or flag_proxy:
                new_user(fp, hash_fp, hash_canvas_fp, '')
            else:
                new_user(fp, hash_fp, hash_canvas_fp, user_ip)
        return render(request, 'report.html',
                      {'flag_new_user': flag_new_user,
                       'fingerprint': fp,
                       'hash_fingerprint': hash_fp,
                       'hash_canvas_fingerprint': hash_canvas_fp,
                       'flag_tor': flag_tor,
                       'flag_vpn': flag_vpn,
                       'flag_proxy': flag_proxy,
                       'proxy_headers': proxy_header,
                       'ip': user_ip})
    return render(request, 'login.html')

