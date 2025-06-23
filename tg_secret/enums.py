from enum import Enum, auto, IntEnum


class ChatRequestResult(Enum):
    ACCEPT = auto()
    IGNORE = auto()
    DISCARD = auto()


class ChatState(IntEnum):
    REQUESTED = 1
    WAITING = 2
    READY = 3
