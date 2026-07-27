"""The exfiltration recorder.

Every "outbound" action the demo agent takes is captured here instead of hitting
the network. This is what makes a deliberately vulnerable agent safe to run in
CI: nothing ever actually leaves the machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ExfilEvent:
    sink: str
    destination: str
    payload: str


@dataclass(slots=True)
class ExfilRecorder:
    events: list[ExfilEvent] = field(default_factory=list)

    def record(self, sink: str, destination: str, payload: str) -> None:
        self.events.append(ExfilEvent(sink=sink, destination=destination, payload=payload))

    def leaked(self, secret: str) -> bool:
        return any(secret in event.payload for event in self.events)

    def destinations(self) -> tuple[str, ...]:
        return tuple(event.destination for event in self.events)
