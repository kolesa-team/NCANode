# cms.verify

Проверяет подпись в CMS

# Запрос

### Параметры запроса

- `checkOcsp` - *(Необязательно)* Осуществлять ли проверку в OCSP
- `checkCrl` - *(Необязательно)* Осуществлять ли проверку в CRL (не сработает, если в конфигурации установлено `crl_enabled=false`)
- `cms` - CMS **в формате Base64**


### Пример запроса

```json
{
    "version": "2.0",
    "method": "cms.verify",
    "params": {
        "checkOcsp": true,
        "checkCrl": true,
        "cms": "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"
    }
}
```

## Ответ

### Пример ответа
```json
{
    "result": {
        "tsp": [
            {
                "tspHashAlgorithm": "SHA256",
                "serialNumber": "...",
                "tsa": null,
                "genTime": "2021-02-18 10:04:45",
                "hash": "...",
                "policy": "1.2.398.3.3.2.6.1"
            },
            {
                "tspHashAlgorithm": "GOST34311",
                "serialNumber": "..",
                "tsa": null,
                "genTime": "2021-02-18 10:04:45",
                "hash": "...",
                "policy": "1.2.398.3.3.2.6.1"
            }
        ],
        "signers": [
            {
                "chain": [
                    {
                        "valid": true,
                        "notAfter": "2022-02-17 11:15:20",
                        "keyUsage": "SIGN",
                        "serialNumber": "...",
                        "subject": {
                            "lastName": "АХМЕТОВИЧ",
                            "country": "KZ",
                            "commonName": "АХМЕТОВ КАЙРАТ",
                            "gender": "MALE",
                            "bin": "...",
                            "surname": "АХМЕТОВ",
                            "organization": "ТОВАРИЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \"...\"",
                            "dn": "CN=АХМЕТОВ КАЙРАТ,SURNAME=АХМЕТОВ,SERIALNUMBER=IIN...,C=KZ,O=ТОВАРИЩЕСТВО С ОГРАНИЧЕННОЙ ОТВЕТСТВЕННОСТЬЮ \\\"...\\\",OU=...,G=АХМЕТОВИЧ,E=EXAMPLE@MAIL.KZ",
                            "birthDate": "YYYY-MM-DD",
                            "email": "EXAMPLE@MAIL.KZ",
                            "iin": "..."
                        },
                        "signAlg": "ECGOST34310",
                        "sign": "...",
                        "publicKey": "...",
                        "issuer": {
                            "commonName": "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST)",
                            "country": "KZ",
                            "dn": "C=KZ,CN=ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST)"
                        },
                        "notBefore": "2021-02-17 11:15:20",
                        "keyUser": [
                            "ORGANIZATION",
                            "EMPLOYEE"
                        ]
                    }
                ],
                "tsps": [
                    {
                        "tspHashAlgorithm": "SHA256",
                        "serialNumber": "...",
                        "tsa": null,
                        "genTime": "2021-02-18 10:04:45",
                        "hash": "...",
                        "policy": "1.2.398.3.3.2.6.1"
                    }
                ],
                "cert": {
                    "valid": true,
                    "notAfter": "2022-02-17 11:15:20",
                    "ocsp": {
                        "revokationReason": 0,
                        "revokationTime": null,
                        "status": "ACTIVE"
                    },
                    "keyUsage": "SIGN",
                    "serialNumber": "...",
                    "subject": {...},
                    "signAlg": "ECGOST34310",
                    "sign": "...",
                    "publicKey": "...",
                    "issuer": {
                        "commonName": "ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST)",
                        "country": "KZ",
                        "dn": "C=KZ,CN=ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST)"
                    },
                    "notBefore": "2021-02-17 11:15:20",
                    "keyUser": [
                        "ORGANIZATION",
                        "EMPLOYEE"
                    ]
                }
            }
        ]
    },
    "message": "",
    "status": 0
}
```

Обратите внимание: в ответе дублируется информация о TSP метках.
Свойство `result.tsp` было в первоначальной версии сервиса и оставлено для обратной совместимости. 
По этому свойству нельзя понять, к какому элементу из `result.signers` относится эта метка.

Поэтому в более поздней версии информация о метках `tsps` добавлена внутрь каждого элемента `result.signers`.

### Параметры ответа
