"""The processing pipeline shared by the worker and the in-memory API mode:

    enrich -> keep raw event -> detect -> score -> store (dedup) -> notify (new alerts only)
"""

from app.detection import DetectionEngine
from app.enrichment import Enricher
from app.events import EventStore
from app.notify import WebhookNotifier
from app.schema import NormalizedEvent
from app.scoring import score
from app.store import AlertStore, StoredAlert


class Pipeline:
    def __init__(
        self,
        engine: DetectionEngine,
        store: AlertStore,
        enricher: Enricher | None = None,
        notifier: WebhookNotifier | None = None,
        events: EventStore | None = None,
    ):
        self.engine = engine
        self.store = store
        self.enricher = enricher
        self.notifier = notifier
        self.events = events

    async def handle(self, events: list[NormalizedEvent]) -> list[StoredAlert]:
        """Process a batch of events and return the alerts it newly created."""
        created = []
        if self.enricher:
            for event in events:
                self.enricher.enrich(event)
        if self.events:
            await self.events.add(events)
        for event in events:
            for alert in self.engine.process(event):
                stored, is_new = await self.store.save(score(alert))
                if is_new:
                    created.append(stored)
        if created and self.notifier:
            await self.notifier.notify(created)
        return created
