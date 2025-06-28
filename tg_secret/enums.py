from enum import Enum, auto, IntEnum, StrEnum


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


class ParseMode(Enum):
    DISABLED = auto()
    DEFAULT = auto()
    MARKDOWN = auto()
    HTML = auto()


class GapsStrategy(Enum):
    # Ignore gaps, overwrite in_seq_no with received out_seq_no
    IGNORE = auto()
    # Request missed messages
    FILL = auto()


class MessageMediaType(StrEnum):
    PHOTO = "photo"
    DOCUMENT = "document"
    AUDIO = "audio"
    CONTACT = "contact"
    LOCATION = "location"
    VIDEO = "video"
    VENUE = "venue"
    WEB_PAGE = "web_page"
