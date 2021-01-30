import requests
import json
from requests.exceptions import HTTPError

import time
import socket


@staticmethod
def send_request(url, method="GET", headers={}, files={}, data={}, params={}, auth=(), cookies={}, timeout=10):
    """
    The generic reaquest method to sent API request to the url
    :param url: The endpoint URL, where request needs to hit
    :param method: The HTTP method for the request, default is GET
    :param headers: The header needs to pass in request, default is empty dict
    :param files: The files needs to pass in request, default is empty dict
    :param data: The payload need to need to send in request, default is empty dict
    :param params: The request params need to send in request, default is empty dict
    :param auth: The username and pass need to send for authentication in request, default is empty tuple
    :param cookies: The cookies need to send in request, default is empty dict
    :return: return response code, response header and response content
    """
    try:
        payload = json.dumps(data)
    except Exception as err:
        print("  Failed to load payload json: " + err)
        return

    print(" +++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(" Sending API Request..!!")
    print(" Request method: {m}".format(m=method))
    print(" Request header: {h}".format(h=headers))
    print(" Request URL: {u}".format(u=url))
    print(" Request Params: {p}".format(p=params))
    print(" Request auth: {a}".format(a=auth))
    print(" Request Cookies: {c}".format(c=cookies))
    print(" Request payload: {p}".format(p=payload))
    print(" Request Files: {f}".format(f=files))
    print(" +++++++++++++++++++++++++++++++++++++++++++++++++++++")

    try:
        # requests.prepare(method=method, url=url, headers=headers, files=files, data=data, params=params, auth=auth, cookies=cookies, hooks=hooks, json=json)
        if method.upper() == "GET":
            response = requests.get(url, params=params, headers=headers, files=files, data=data, auth=auth,
                                    cookies=cookies, timeout=timeout)

        elif method.upper() == "POST":
            response = requests.post(url, data=payload, headers=headers, files=files, params=params, auth=auth,
                                     cookies=cookies, timeout=timeout)

        elif method.upper() == "PUT":
            response = requests.put(url, data=payload, headers=headers, files=files, params=params, auth=auth,
                                    cookies=cookies, timeout=timeout)

        elif method.upper() == "PATCH":
            response = requests.patch(url, data=payload, headers=headers, files=files, params=params, auth=auth,
                                      cookies=cookies, timeout=timeout)

        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, files=files, data=payload, params=params, auth=auth,
                                       cookies=cookies, timeout=timeout)
        print(" success..!!")
        print(" Response status: {}".format(str(response.status_code)))
        print(" Response header: {}".format(str(response.headers)))
        # print(" Response body: {}".format(str(response.content)))
        print(" Redirected URL: {}".format(str(response.url)))

    except HTTPError as http_err:
        print(" HTTP Error: {}".format(http_err))
        return

    except Exception as err:
        print(" Error: {}".format(err))
        return

    return response.status_code, response.headers, response.content, response.url

@staticmethod
def send_udp_packet(udp_server_ip, udp_port, msg):
    new_msg = bytes(str(msg), 'utf-8')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(new_msg, (udp_server_ip, udp_port))
    except Exception as err:
        print(udp_server_ip + " Connection Failed for given server " + err)

@staticmethod
def send_request_get_response_dict(url, method="GET", headers={}, files={}, data={}, params={}, auth=(), cookies={},
                                   timeout=10, is_json_data=True):
    """
    The generic reaquest method to sent API request to the url
    :param url: The endpoint URL, where request needs to hit
    :param method: The HTTP method for the request, default is GET
    :param headers: The header needs to pass in request, default is empty dict
    :param files: The files needs to pass in request, default is empty dict
    :param data: The payload need to need to send in request, default is empty dict
    :param params: The request params need to send in request, default is empty dict
    :param auth: The username and pass need to send for authentication in request, default is empty tuple
    :param cookies: The cookies need to send in request, default is empty dict
    :return: return response dict
    """
    response_dict = {}
    if is_json_data:
        try:
            payload = json.dumps(data)
        except Exception as err:
            print(" Failed to load payload json: " + err)
            return
    else:
        payload = data.replace('\n', '\n\r')
    print(" +++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print(" Sending API Request..!!")
    print(" Request method: {m}".format(m=method))
    print(" Request header: {h}".format(h=headers))
    print(" Request URL: {u}".format(u=url))
    print(" Request Params: {p}".format(p=params))
    print(" Request auth: {a}".format(a=auth))
    print(" Request Cookies: {c}".format(c=cookies))
    print(" Request payload: {p}".format(p=payload))
    print(" Request Files: {f}".format(f=files))
    print(" +++++++++++++++++++++++++++++++++++++++++++++++++++++")
    # Creating session
    session = requests.session()
    try:
        # requests.prepare(method=method, url=url, headers=headers, files=files, data=data, params=params, auth=auth, cookies=cookies, hooks=hooks, json=json)
        if method.upper() == "GET":
            response = requests.get(url, params=params, headers=headers, files=files, data=data, auth=auth,
                                    cookies=cookies, timeout=timeout)

        elif method.upper() == "POST":
            response = requests.post(url, data=payload, headers=headers, files=files, params=params, auth=auth,
                                     cookies=cookies, timeout=timeout)

        elif method.upper() == "PUT":
            response = requests.put(url, data=payload, headers=headers, files=files, params=params, auth=auth,
                                    cookies=cookies, timeout=timeout)

        elif method.upper() == "PATCH":
            response = requests.patch(url, data=payload, headers=headers, files=files, params=params, auth=auth,
                                      cookies=cookies, timeout=timeout)

        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, files=files, data=payload, params=params, auth=auth,
                                       cookies=cookies, timeout=timeout)
        print(" success..!!")
        print(" Response status: {}".format(str(response.status_code)))
        print(" Response header: {}".format(str(response.headers)))
        # print(" Response body: {}".format(str(response.content)))
        print(" Redirected URL: {}".format(str(response.url)))

    except HTTPError as http_err:
        print(" HTTP Error: {}".format(http_err))
        return

    except Exception as err:
        print(" Error: {}".format(err))
        return
    # Assigning in response_dict
    response_dict['response'] = response
    response_dict['session'] = session

    return response_dict




