class SecretException(Exception):
    ...


class SecretChatStateException(SecretException):
    def __init__(self, message: str) -> None:
        super().__init__(f"Chat has invalid state: {message}")


class SecretChatNotReadyException(SecretChatStateException):
    def __init__(self):
        super().__init__("chat is not ready for sending messages yet.")


class SecretLayerException(SecretException):
    def __init__(self, feature: str, peer_layer: int, need_layer: int) -> None:
        super().__init__(f"Peer does not support {feature}. Peer layer is {peer_layer}, but {need_layer} is needed.")

        self.feature = feature
        self.peer_layer = peer_layer
        self.need_layer = need_layer


class SecretSecurityException(SecretException):
    @classmethod
    def check(cls, cond: bool, msg: str):
        if not cond:
            raise cls(f"Security check failed: {msg}")
