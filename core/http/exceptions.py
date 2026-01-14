class HTTPClientError(Exception):
    pass


class HTTPTimeoutError(HTTPClientError):
    pass


class HTTPRateLimitError(HTTPClientError):
    pass


class HTTPServerError(HTTPClientError):
    pass
