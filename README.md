# Hikvision-OpenAPI-Signer: 海康威视iSecure Center综合安防管理平台OpenAPI网关Artemis接口请求签名Python模块

## 功能

对OpenAPI网关Artemis接口请求进行签名。

## 安装

`pip install hikvision-openapi-signer`

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

## 参考文档

[综合安防管理平台（iSecure Center）文档](https://open.hikvision.com/docs/docId?productId=5c67f1e2f05948198c909700)
