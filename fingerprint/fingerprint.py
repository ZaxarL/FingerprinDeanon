from django import template
from django.core.handlers.wsgi import WSGIRequest
from django.utils.datastructures import MultiValueDictKeyError
from werkzeug.local import LocalProxy
import json
import hashlib


def get(request: WSGIRequest or LocalProxy):
    print(request)
    request_type = type(request)
    if request_type not in (LocalProxy, WSGIRequest):
        raise TypeError(
            "get() argument must be WSGIRequest or LocalProxy, not {type}"
                .format(type=request_type)
        )

    try:
        fp = request.POST
        hash_fp = fp['hash_fingerprint']
        fp = fp['fingerprint']
    except AttributeError:
        fp = request.form
        hash_fp = fp['hash_fingerprint']
        fp = fp['fingerprint']
    except MultiValueDictKeyError:
        raise template.TemplateSyntaxError(
            "Missing fingerprint field in {path}"
                .format(path=request.path))

    if not fp:
        raise ConnectionError("Failed to load JS on client")
    else:
        parsed_json = json.loads(fp)
        # print(parsed_json)
        canvas_fingerprint = parsed_json['components']['canvas']['value']['geometry']
        hash_canvas_fingerprint = hashlib.sha3_256(canvas_fingerprint.encode('utf-8')).hexdigest()
        # print(canvas_fingerprint_hash)
        # print(socket.gethostbyname(socket.gethostname()))
        # print(hash_fp)
        return parsed_json, hash_fp, hash_canvas_fingerprint


