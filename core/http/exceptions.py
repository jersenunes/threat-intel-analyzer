class HTTPClientError(Exception):
    pass


class HTTPTimeoutError(HTTPClientError):
    pass


class HTTPRateLimitError(HTTPClientError):
    pass


class HTTPServerError(HTTPClientError):
    pass

class InvalidAPIKey(Exception):
    def __init__(self, value=None):
        self.value = value or "Invalid API Key"

    def __str__(self):
        return repr(self.value)
