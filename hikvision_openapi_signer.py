# Copyright 2025 Accurio (https://github.com/Accurio)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
海康威视iSecure Center综合安防管理平台OpenAPI网关Artemis接口请求签名模块

## 示例

- 使用requests作为HTTP客户端
```python
>>> import requests
>>> from hikvision_openapi_signer import HikvisionOpenAPISigner
>>> signer = HikvisionOpenAPISigner("https://isc.example.com",
...     12345678, 'abcdefghijklmnopqrst', headers={'tagId': 0})
>>> method, url, headers, body = signer.sign('POST', '/api/resource/v1/org/advance/orgList',
...     jsons={'pageNo': 1, 'pageSize': 1}, accept='application/json')
>>> response = requests.request(method, url, headers=headers, data=body)
>>> response.json()
{'code': '0', 'msg': 'success', 'data': ...}
```

- 使用HTTPX作为异步HTTP客户端
```python
>>> import httpx
>>> from hikvision_openapi_signer import HikvisionOpenAPISigner
>>> client = httpx.AsyncClient()
>>> signer = HikvisionOpenAPISigner("https://isc.example.com",
...     12345678, 'abcdefghijklmnopqrst', headers={'tagId': 0})
>>> method, url, headers, body = signer.sign('POST', '/api/resource/v1/org/advance/orgList',
...     jsons={'pageNo': 1, 'pageSize': 1}, accept='application/json')
>>> response = await client.request(method, url, headers=headers, content=body)
>>> response.json()
{'code': '0', 'msg': 'success', 'data': ...}
```
"""

from collections.abc import Sequence, Mapping, MutableMapping
from typing import Any, Union, Optional
import base64
import email.utils
import hashlib
import hmac
import json
import time
import urllib.parse
import uuid


JSONValue = Union[None, bool, int, float, str, Sequence['JSONValue'], Mapping[str, 'JSONValue']]
JSONObject = Mapping[str, JSONValue]


class HikvisionOpenAPISigner:
    """
    海康威视iSecure Center综合安防管理平台OpenAPI网关Artemis接口请求签名类

    Attributes:
        scheme_and_authority (str): Artemis接口地址
        key (Union[int, str]): Key
        secret (str): Secret
        artemis_path_prefix (str): Artemis接口路径
        signature_headers_excluded (set[str]): 不参与签名计算的标头
    """

    headers_signature_excluded: set[str] = {'Accept', 'Content-Md5',
        'Content-Type', 'Date', 'X-Ca-Signature', 'X-Ca-Signature-Headers'}

    @staticmethod
    def _normalize_headers(headers: Optional[Mapping[str, Any]] = None) -> dict[str, str]:
        return {k.title(): str(v) for k, v in headers.items()} if headers else {}

    def __init__(self, scheme_and_authority: str,
        key: Union[int, str], secret: str,
        headers: Optional[Mapping[str, Any]] = None,
        artemis_path_prefix: str = '/artemis',
    ) -> None:
        """
        海康威视iSecure Center综合安防管理平台OpenAPI网关Artemis接口请求签名类

        Args:
            scheme_and_authority (str): Artemis接口地址，如'https://isc.example.com:8443'
            key (Union[int, str]): Key
            secret (str): Secret
            artemis_path_prefix (str): Artemis接口路径，默认为'/artemis'
        """
        self.scheme_and_authority = scheme_and_authority
        self.key = str(key)
        self.secret = secret
        self.headers = self._normalize_headers(headers)
        self.artemis_path_prefix = artemis_path_prefix


    def sign(self, method: str, path: str, *,
        querys:  Optional[Mapping[str, Any]] = None,
        headers: Optional[MutableMapping[str, Any]] = None,
        body:  Optional[str | bytes] = None,
        forms: Optional[Mapping[str, Any]] = None,
        jsons: Optional[JSONObject] = None,
        content_type: Optional[str] = None,
        accept:       Optional[str] = None,
    ) -> tuple[str, str, dict[str, str], Union[str, bytes, None]]:
        """
        对OpenAPI网关Artemis接口请求进行签名

        Args:
            method (str): HTTP方法
            path (str): Artemis接口路径
            querys  (Optional[Mapping[str, Any]]): 查询
            headers (Optional[MutableMapping[str, Any]]): 标头
            body  (Optional[str | bytes]): 主体
            forms (Optional[Mapping[str, Any]): 表单
            jsons (Optional[JSONObject]): JSON
            content_type (Optional[str]): Content-Type标头
            accept       (Optional[str]): Accept标头
        Returns:
            (str, str, dict[str, str], Union[str, bytes, None]): HTTP方法, URL, 标头, 主体
        """
        method = method.upper()
        headers = self.headers | self._normalize_headers(headers)

        if isinstance(body, bytes):
            headers.setdefault('Content-Type', 'application/octet-stream')
        elif isinstance(body, str):
            headers.setdefault('Content-Type', 'text/plain')
        elif forms is not None:
            body = urllib.parse.urlencode(forms)
            headers.setdefault('Content-Type',
                'application/x-www-form-urlencoded; charset=utf-8')
        elif jsons is not None:
            body = json.dumps(jsons)
            headers.setdefault('Content-Type', 'application/json')

        if body and isinstance(body, (bytes, str)):
            digest = hashlib.md5(body.encode() if isinstance(body, str) else body).digest()
            headers['Content-Md5'] = base64.b64encode(digest).decode()

        if content_type is not None:
            headers['Content-Type'] = content_type
        if accept is not None:
            headers['Accept'] = accept
        else:
            headers.setdefault('Accept', '*/*')

        timestamp = time.time_ns()
        headers.setdefault('Date', email.utils.formatdate(timestamp/1e9, usegmt=True))
        headers.setdefault('X-Ca-Key', self.key)
        headers.setdefault('X-Ca-Timestamp', str(timestamp//1_000_000))
        headers.setdefault('X-Ca-Nonce', str(uuid.uuid4()))
        self._sign(method, path, headers, querys, forms)

        url = self.scheme_and_authority + self.artemis_path_prefix + path
        if querys:
            url += '?' + urllib.parse.urlencode(querys)
        return method, url, headers, body


    def _sign(self, method: str, path: str,
        headers: MutableMapping[str, str],
        querys: Optional[Mapping[str, Any]], forms: Optional[Mapping[str, Any]],
    ) -> None:
        """
        计算和设置X-Ca-Signature相关签名标头
        """
        s = method + '\n'

        for key in ('Accept', 'Content-Md5', 'Content-Type', 'Date'):
            value = headers.get(key)
            if value is None:
                continue
            if key == 'Content-Type':
                values = value.split(';')
                if values[-1].strip().lower().startswith('boundary'):
                    value = ';'.join(values[:-1])
            s += value + '\n'

        headers_signature = sorted(set(headers) - self.headers_signature_excluded)
        s += ''.join(f"{k.lower()}:{headers[k].strip()}\n" for k in headers_signature)
        headers['X-Ca-Signature-Headers'] = ','.join(headers_signature)

        s += self.artemis_path_prefix + path

        querys_and_forms: dict[str, Any] = {}
        if querys is not None:
            querys_and_forms.update(querys)
        if forms is not None:
            querys_and_forms.update(forms)
        if len(querys_and_forms) > 0:
            s += '?' + urllib.parse.urlencode(
                [(k, querys_and_forms[k]) for k in sorted(querys_and_forms)])

        signature = hmac.digest(self.secret.encode(), s.encode(), hashlib.sha256)
        headers['X-Ca-Signature'] = base64.b64encode(signature).decode()
