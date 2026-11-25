"""异常类型。HTTP 适配层把它们映射为对应状态码。"""


class RightsError(Exception):
    status = 400
    code = "rights_error"

    def __init__(self, message, *, code=None, details=None):
        super().__init__(message)
        self.message = message
        self.code = code or type(self).code
        self.details = details or {}

    def as_dict(self):
        result = {"error": self.code, "message": self.message}
        if self.details:
            result["details"] = self.details
        return result


class ValidationError(RightsError):
    status = 400
    code = "invalid_request"


class Forbidden(RightsError):
    status = 403
    code = "forbidden"


class NotFound(RightsError):
    status = 404
    code = "not_found"


class Conflict(RightsError):
    status = 409
    code = "conflict"
