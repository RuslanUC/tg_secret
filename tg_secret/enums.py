from enum import Enum, auto, IntEnum


class ChatRequestResult(Enum):
    ACCEPT = auto()
    IGNORE = auto()
    DISCARD = auto()


class ChatState(IntEnum):
    # Incoming request
    REQUESTED = 1
    # Outgoing request
    WAITING = 2
    # Accepted chat
    READY = 3
