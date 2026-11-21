import base64

from malduck import procmem, xor
from malduck.extractor import Extractor


class Nested(Extractor):
    """
    Multi-stage dropper. Payload layout at the matched offset:

    ``"NESTEDLAYER:" + u32le declared length + xor(0x42)-encoded payload``
    """

    family = "nested"
    yara_rules = ("NestedLayer",)

    @Extractor.extractor("layer")
    def layer(self, p, hit):
        declared = p.uint32v(hit + 12)
        blob = p.readv(hit + 16, declared)
        if len(blob) < declared:
            # Truncated payload: stop this branch, keep what we have
            return {"truncated": True}
        if not declared:
            return {"layers": [hit]}
        decoded = xor(0x42, blob)
        self.push_procmem(
            procmem(decoded),
            offset=hit + 16,
            length=declared,
            encoding="xor:0x42",
        )
        return {"layers": [hit]}


class Alien(Extractor):
    """
    Unrelated family whose structures may be mixed into nested buffers
    """

    family = "alien"
    yara_rules = ("AlienStruct",)

    @Extractor.extractor("alien")
    def alien(self, p, hit):
        return {"alien_marker": [hit]}


class Looper(Extractor):
    """
    Each layer decodes to a payload that decodes back to the previous one
    """

    family = "looper"
    yara_rules = ("CircularPayload",)

    @Extractor.extractor("loop")
    def loop(self, p, hit):
        self.push_procmem(procmem(xor(0x42, p.readp(0))), encoding="xor:0x42")
        return {"looped": True}


class Bomber(Extractor):
    """
    Each layer produces a slightly longer payload (nesting bomb)
    """

    family = "bomber"
    yara_rules = ("DepthPayload",)

    @Extractor.extractor("bomb")
    def bomb(self, p, hit):
        self.push_procmem(procmem(p.readp(0) + b"B"))
        return {"bombed": True}


class Faulty(Extractor):
    """
    One method pushes a strong config, another fails to decode the payload
    """

    family = "faulty"
    yara_rules = ("FaultyPayload",)

    @Extractor.extractor("fault_marker")
    def marker(self, p, hit):
        return {"attempted": True}

    @Extractor.extractor("fault_payload")
    def payload(self, p, hit):
        blob = p.readv(hit + 11, 16)
        decoded = base64.b64decode(blob, validate=True)
        self.push_procmem(procmem(decoded), encoding="base64")
        return {"decoded": True}
